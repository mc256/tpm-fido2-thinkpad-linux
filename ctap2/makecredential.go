package ctap2

import (
	"context"
	"crypto/sha256"
	"log"
	"math/big"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// MakeCredential handles the authenticatorMakeCredential command
func (h *Handler) MakeCredential(ctx context.Context, req *MakeCredentialRequest) (byte, []byte) {
	log.Printf("CTAP2 MakeCredential: RP=%s, User=%s", req.RP.ID, req.User.Name)
	log.Printf("CTAP2 MakeCredential: Options=%+v", req.Options)
	log.Printf("CTAP2 MakeCredential: Extensions=%+v", req.Extensions)

	// Validate clientDataHash
	if len(req.ClientDataHash) != 32 {
		log.Printf("CTAP2 MakeCredential: Invalid clientDataHash length: %d", len(req.ClientDataHash))
		return StatusInvalidParameter, nil
	}

	// Check if at least one supported algorithm is requested
	es256Supported := false
	for _, param := range req.PubKeyCredParams {
		if param.Type == CredentialTypePublicKey && param.Alg == COSEAlgES256 {
			es256Supported = true
			break
		}
	}
	if !es256Supported {
		log.Printf("CTAP2 MakeCredential: ES256 not in requested algorithms")
		return StatusUnsupportedExtension, nil // Actually should be unsupported algorithm
	}

	// Check excludeList for existing credentials
	rpIDHash := HashRPID(req.RP.ID)
	for _, excluded := range req.ExcludeList {
		// Try to verify if this credential exists by attempting to sign
		dummyHash := sha256.Sum256([]byte("exclude-check"))
		_, err := h.signer.SignASN1(excluded.ID, rpIDHash[:], dummyHash[:])
		if err == nil {
			// Credential exists and is valid - need user presence to confirm exclusion
			log.Printf("CTAP2 MakeCredential: Credential in excludeList exists")
			return StatusCredentialExcluded, nil
		}
	}

	// Request user presence
	var challengeParam, appParam [32]byte
	copy(challengeParam[:], req.ClientDataHash)
	copy(appParam[:], rpIDHash[:])

	pinResultCh, err := h.presence.ConfirmPresence("FIDO2 Confirm Register", challengeParam, appParam)
	if err != nil {
		log.Printf("CTAP2 MakeCredential: user presence error: %s", err)
		return StatusOperationDenied, nil
	}

	// Wait for user response with timeout
	childCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	select {
	case result := <-pinResultCh:
		if !result.OK {
			log.Printf("CTAP2 MakeCredential: User denied or error: %v", result.Error)
			return StatusOperationDenied, nil
		}
	case <-childCtx.Done():
		log.Printf("CTAP2 MakeCredential: User presence timeout")
		return StatusUserActionTimeout, nil
	}

	// Check if resident key is requested
	residentKeyRequested := false
	if req.Options != nil {
		if rk, ok := req.Options["rk"]; ok && rk {
			residentKeyRequested = true
		}
	}

	// Generate credential
	credentialID, x, y, err := h.signer.RegisterKey(rpIDHash[:])
	if err != nil {
		log.Printf("CTAP2 MakeCredential: RegisterKey error: %s", err)
		return StatusOther, nil
	}

	log.Printf("CTAP2 MakeCredential: Generated credential, ID length=%d, residentKey=%v", len(credentialID), residentKeyRequested)

	// Save resident credential if requested
	if residentKeyRequested && h.storage != nil {
		cred := &CredentialMetadata{
			RPID:            req.RP.ID,
			RPName:          req.RP.Name,
			UserID:          req.User.ID,
			UserName:        req.User.Name,
			UserDisplayName: req.User.DisplayName,
			CredentialID:    credentialID,
			PublicKeyX:      bigIntToBytes(x),
			PublicKeyY:      bigIntToBytes(y),
			CreatedAt:       time.Now(),
		}
		if err := h.storage.Save(cred); err != nil {
			log.Printf("CTAP2 MakeCredential: Failed to save resident credential: %s", err)
			// Continue anyway - the credential is still valid, just not discoverable
		}
	}

	// Build COSE public key
	coseKey, err := BuildCOSEPublicKeyES256(x, y)
	if err != nil {
		log.Printf("CTAP2 MakeCredential: COSE key build error: %s", err)
		return StatusOther, nil
	}

	// Build extensions output if hmac-secret was requested
	var extensionsOutput []byte
	hmacSecretRequested := false
	if req.Extensions != nil {
		if _, ok := req.Extensions["hmac-secret"]; ok {
			hmacSecretRequested = true
			extMap := map[string]bool{"hmac-secret": true}
			extensionsOutput, _ = ctapEncMode.Marshal(extMap)
		}
	}

	// Build flags
	flags := byte(FlagUserPresent | FlagUserVerified | FlagAttestedCredData)
	if hmacSecretRequested {
		flags |= FlagExtensionData
	}

	// Build AuthenticatorData
	authData := &AuthenticatorData{
		RPIDHash:  rpIDHash,
		Flags:     flags,
		SignCount: h.signer.Counter(),
		AttestedCredentialData: &AttestedCredentialData{
			AAGUID:              h.aaguid,
			CredentialID:        credentialID,
			CredentialPublicKey: coseKey,
		},
		Extensions: extensionsOutput,
	}

	authDataBytes := authData.Marshal()

	// Build response using self-attestation ("none" format): no attestation
	// certificate or signature, just the authenticator data. Avoids relying
	// parties that strictly validate attestation certificate fields (e.g.
	// requiring a Subject Country code) rejecting our self-signed cert.
	resp := &MakeCredentialResponse{
		Fmt:      "none",
		AuthData: authDataBytes,
		AttStmt:  map[string]interface{}{},
	}

	encoded, err := ctapEncMode.Marshal(resp)
	if err != nil {
		log.Printf("CTAP2 MakeCredential: Response encode error: %s", err)
		return StatusOther, nil
	}

	log.Printf("CTAP2 MakeCredential: Success, response=%d bytes", len(encoded))
	return StatusSuccess, encoded
}

// parseMakeCredentialRequest parses the CBOR-encoded MakeCredential request
func parseMakeCredentialRequest(data []byte) (*MakeCredentialRequest, error) {
	var req MakeCredentialRequest
	if err := cbor.Unmarshal(data, &req); err != nil {
		return nil, err
	}
	return &req, nil
}

// bigIntToBytes converts a big.Int to a fixed 32-byte slice (for P-256 coordinates)
func bigIntToBytes(n *big.Int) []byte {
	b := n.Bytes()
	// Pad to 32 bytes if needed
	if len(b) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(b):], b)
		return padded
	}
	return b
}

// MakeCredentialParams contains the parameters for MakeCredentialDirect
type MakeCredentialParams struct {
	ClientDataHash  []byte
	RPID            string
	RPName          string
	UserID          []byte
	UserName        string
	UserDisplayName string
	ResidentKey     bool   // Whether to store as resident key
	HmacSecret      bool   // Whether hmac-secret extension was requested
	ExcludeList     [][]byte // List of credential IDs to exclude
}

// MakeCredentialDirect creates a credential without user presence handling.
// The caller is responsible for confirming user presence before calling this method.
// This method is designed for Native Messaging where the webauthn handler controls the flow.
func (h *Handler) MakeCredentialDirect(ctx context.Context, params *MakeCredentialParams) (*MakeCredentialResult, error) {
	log.Printf("CTAP2 MakeCredentialDirect: RP=%s, User=%s, ResidentKey=%v", params.RPID, params.UserName, params.ResidentKey)

	// Validate clientDataHash
	if len(params.ClientDataHash) != 32 {
		return nil, ErrInvalidParameter
	}

	// Compute rpIdHash
	rpIDHash := HashRPID(params.RPID)

	// Check excludeList for existing credentials
	for _, excludedID := range params.ExcludeList {
		// Try to verify if this credential exists by attempting to sign
		dummyHash := sha256.Sum256([]byte("exclude-check"))
		_, err := h.signer.SignASN1(excludedID, rpIDHash[:], dummyHash[:])
		if err == nil {
			// Credential exists and is valid
			log.Printf("CTAP2 MakeCredentialDirect: Credential in excludeList exists")
			return nil, ErrCredentialExcluded
		}
	}

	// Generate credential
	credentialID, x, y, err := h.signer.RegisterKey(rpIDHash[:])
	if err != nil {
		log.Printf("CTAP2 MakeCredentialDirect: RegisterKey error: %s", err)
		return nil, err
	}

	log.Printf("CTAP2 MakeCredentialDirect: Generated credential, ID length=%d, residentKey=%v", len(credentialID), params.ResidentKey)

	// Save resident credential if requested
	if params.ResidentKey && h.storage != nil {
		cred := &CredentialMetadata{
			RPID:            params.RPID,
			RPName:          params.RPName,
			UserID:          params.UserID,
			UserName:        params.UserName,
			UserDisplayName: params.UserDisplayName,
			CredentialID:    credentialID,
			PublicKeyX:      bigIntToBytes(x),
			PublicKeyY:      bigIntToBytes(y),
			CreatedAt:       time.Now(),
		}
		if err := h.storage.Save(cred); err != nil {
			log.Printf("CTAP2 MakeCredentialDirect: Failed to save resident credential: %s", err)
			// Continue anyway - the credential is still valid, just not discoverable
		}
	}

	// Build COSE public key
	coseKey, err := BuildCOSEPublicKeyES256(x, y)
	if err != nil {
		log.Printf("CTAP2 MakeCredentialDirect: COSE key build error: %s", err)
		return nil, err
	}

	// Build extensions output if hmac-secret was requested
	var extensionsOutput []byte
	if params.HmacSecret {
		extMap := map[string]bool{"hmac-secret": true}
		extensionsOutput, _ = ctapEncMode.Marshal(extMap)
	}

	// Build flags
	flags := byte(FlagUserPresent | FlagUserVerified | FlagAttestedCredData)
	if params.HmacSecret {
		flags |= FlagExtensionData
	}

	// Build AuthenticatorData
	authData := &AuthenticatorData{
		RPIDHash:  rpIDHash,
		Flags:     flags,
		SignCount: h.signer.Counter(),
		AttestedCredentialData: &AttestedCredentialData{
			AAGUID:              h.aaguid,
			CredentialID:        credentialID,
			CredentialPublicKey: coseKey,
		},
		Extensions: extensionsOutput,
	}

	authDataBytes := authData.Marshal()

	// Build attestation object (CBOR-encoded) using self-attestation ("none"
	// format): no attestation certificate or signature. Avoids relying
	// parties that strictly validate attestation certificate fields (e.g.
	// requiring a Subject Country code) rejecting our self-signed cert.
	attObj := map[string]interface{}{
		"fmt":      "none",
		"authData": authDataBytes,
		"attStmt":  map[string]interface{}{},
	}

	attestationObject, err := ctapEncMode.Marshal(attObj)
	if err != nil {
		log.Printf("CTAP2 MakeCredentialDirect: Attestation object encode error: %s", err)
		return nil, err
	}

	log.Printf("CTAP2 MakeCredentialDirect: Success, credentialID=%d bytes, attestationObject=%d bytes", len(credentialID), len(attestationObject))

	return &MakeCredentialResult{
		CredentialID:      credentialID,
		AttestationObject: attestationObject,
		AuthData:          authDataBytes,
		PublicKeyX:        x,
		PublicKeyY:        y,
		HmacSecretEnabled: params.HmacSecret,
	}, nil
}
