package webauthn

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"time"

	"github.com/psanford/tpm-fido/ctap2"
	"github.com/psanford/tpm-fido/nativemsg"
)

// hashPRFSalt hashes a PRF salt according to the WebAuthn PRF extension spec:
// SHA-256("WebAuthn PRF" || 0x00 || salt)
func hashPRFSalt(salt []byte) []byte {
	h := sha256.New()
	h.Write([]byte("WebAuthn PRF"))
	h.Write([]byte{0x00})
	h.Write(salt)
	return h.Sum(nil)
}

// Handler handles WebAuthn requests via Native Messaging
type Handler struct {
	ctap2Handler *ctap2.Handler
}

// NewHandler creates a new WebAuthn handler
func NewHandler(ctap2Handler *ctap2.Handler) *Handler {
	return &Handler{
		ctap2Handler: ctap2Handler,
	}
}

// HandleRequest processes a Native Messaging request and returns the response
func (h *Handler) HandleRequest(ctx context.Context, msg json.RawMessage) interface{} {
	// Parse the request envelope
	var envelope nativemsg.RequestEnvelope
	if err := json.Unmarshal(msg, &envelope); err != nil {
		log.Printf("WebAuthn: Failed to parse request envelope: %v", err)
		return NewErrorResponse("", "", ErrNameTypeError, "Invalid request format")
	}

	log.Printf("WebAuthn: Received %s request, requestId=%s, origin=%s", envelope.Type, envelope.RequestID, envelope.Origin)

	// H1: Validate that origin is a well-formed HTTPS URL
	if err := validateOrigin(envelope.Origin); err != nil {
		log.Printf("WebAuthn: Invalid origin %q: %v", envelope.Origin, err)
		return NewErrorResponse(envelope.Type, envelope.RequestID, ErrNameTypeError, "Invalid origin: must be an HTTPS URL")
	}

	switch envelope.Type {
	case "create":
		return h.handleCreate(ctx, envelope.RequestID, envelope.Origin, envelope.Options)
	case "get":
		return h.handleGet(ctx, envelope.RequestID, envelope.Origin, envelope.Options)
	default:
		return NewErrorResponse(envelope.Type, envelope.RequestID, ErrNameTypeError, "Unknown request type")
	}
}

// handleCreate handles navigator.credentials.create() requests
func (h *Handler) handleCreate(ctx context.Context, requestID, origin string, optionsRaw json.RawMessage) interface{} {
	// Parse create options
	var options CreateOptions
	if err := json.Unmarshal(optionsRaw, &options); err != nil {
		log.Printf("WebAuthn Create: Failed to parse options: %v", err)
		return NewErrorResponse("create", requestID, ErrNameTypeError, "Invalid create options")
	}

	// H2: Validate RP ID is a registrable domain suffix of the origin
	if err := validateRPID(origin, options.RP.ID); err != nil {
		log.Printf("WebAuthn Create: RP ID validation failed: %v", err)
		return NewErrorResponse("create", requestID, ErrNameTypeError, "RP ID does not match origin")
	}

	// Decode challenge
	challenge, err := base64.StdEncoding.DecodeString(options.Challenge)
	if err != nil {
		log.Printf("WebAuthn Create: Failed to decode challenge: %v", err)
		return NewErrorResponse("create", requestID, ErrNameTypeError, "Invalid challenge encoding")
	}

	// Decode user ID
	userID, err := base64.StdEncoding.DecodeString(options.User.ID)
	if err != nil {
		log.Printf("WebAuthn Create: Failed to decode user ID: %v", err)
		return NewErrorResponse("create", requestID, ErrNameTypeError, "Invalid user ID encoding")
	}

	// Check for ES256 support
	es256Supported := false
	for _, param := range options.PubKeyCredParams {
		if param.Type == "public-key" && param.Alg == -7 {
			es256Supported = true
			break
		}
	}
	if !es256Supported {
		log.Printf("WebAuthn Create: ES256 not in requested algorithms")
		return NewErrorResponse("create", requestID, ErrNameTypeError, "ES256 algorithm required")
	}

	// Build clientDataJSON
	clientDataJSON, err := BuildClientDataJSON(ClientDataTypeCreate, challenge, origin)
	if err != nil {
		log.Printf("WebAuthn Create: Failed to build clientDataJSON: %v", err)
		return NewErrorResponse("create", requestID, ErrNameUnknown, "Failed to build client data")
	}
	clientDataHash := ClientDataHash(clientDataJSON)

	// Determine if resident key is requested
	residentKey := false
	if options.AuthenticatorSelection != nil {
		rk := options.AuthenticatorSelection.ResidentKey
		if rk == "required" || rk == "preferred" {
			residentKey = true
		}
	}

	// Check if hmac-secret/PRF is requested
	hmacSecretRequested := false
	var prfEval *PRFEval
	if options.Extensions != nil && options.Extensions.PRF != nil {
		hmacSecretRequested = true
		prfEval = options.Extensions.PRF.Eval
	}

	// Decode exclude list
	excludeList := make([][]byte, 0, len(options.ExcludeCredentials))
	for _, cred := range options.ExcludeCredentials {
		credID, err := base64.StdEncoding.DecodeString(cred.ID)
		if err != nil {
			continue
		}
		excludeList = append(excludeList, credID)
	}

	// Request user presence
	var challengeParam, appParam [32]byte
	copy(challengeParam[:], clientDataHash[:])
	rpIDHash := ctap2.HashRPID(options.RP.ID)
	copy(appParam[:], rpIDHash[:])

	presence := h.ctap2Handler.Presence()
	resultCh, err := presence.ConfirmPresence("Register with "+options.RP.Name, challengeParam, appParam)
	if err != nil {
		log.Printf("WebAuthn Create: User presence error: %v", err)
		return MapErrorToResponse("create", requestID, ErrUserDenied)
	}

	// Get timeout from options or use default
	timeout := 60 * time.Second
	if options.Timeout > 0 {
		timeout = time.Duration(options.Timeout) * time.Millisecond
	}

	// Wait for user presence
	childCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	select {
	case result := <-resultCh:
		if !result.OK {
			log.Printf("WebAuthn Create: User denied or error: %v", result.Error)
			if result.Error != nil && result.Error.Error() == "fingerprint verification timed out" {
				return MapErrorToResponse("create", requestID, ErrTimeout)
			}
			return MapErrorToResponse("create", requestID, ErrUserDenied)
		}
	case <-childCtx.Done():
		log.Printf("WebAuthn Create: User presence timeout")
		return MapErrorToResponse("create", requestID, ErrTimeout)
	}

	// Create the credential
	params := &ctap2.MakeCredentialParams{
		ClientDataHash:  clientDataHash[:],
		RPID:            options.RP.ID,
		RPName:          options.RP.Name,
		UserID:          userID,
		UserName:        options.User.Name,
		UserDisplayName: options.User.DisplayName,
		ResidentKey:     residentKey,
		HmacSecret:      hmacSecretRequested,
		ExcludeList:     excludeList,
	}

	result, err := h.ctap2Handler.MakeCredentialDirect(ctx, params)
	if err != nil {
		log.Printf("WebAuthn Create: MakeCredential error: %v", err)
		if errors.Is(err, ctap2.ErrCredentialExcluded) {
			return MapErrorToResponse("create", requestID, ErrCredentialExcluded)
		}
		return MapErrorToResponse("create", requestID, err)
	}

	// Compute PRF during create if requested
	var prfResult *PRFResult
	if hmacSecretRequested {
		prfResult = &PRFResult{
			Enabled: true,
		}

		// If PRF eval was requested, compute the outputs
		if prfEval != nil {
			log.Printf("WebAuthn Create: PRF salt1 received: %q (len=%d)", prfEval.First, len(prfEval.First))
			rawSalt1, err := base64.StdEncoding.DecodeString(prfEval.First)
			if err != nil {
				log.Printf("WebAuthn Create: Invalid PRF salt1 base64: %v", err)
				return NewErrorResponse("create", requestID, ErrNameTypeError, "Invalid PRF salt")
			}
			// Hash the salt per WebAuthn PRF extension spec
			salt1 := hashPRFSalt(rawSalt1)
			log.Printf("WebAuthn Create: PRF salt1 hashed: %d bytes -> 32 bytes", len(rawSalt1))

			var salt2 []byte
			if prfEval.Second != "" {
				rawSalt2, err := base64.StdEncoding.DecodeString(prfEval.Second)
				if err != nil {
					log.Printf("WebAuthn Create: Invalid PRF salt2 base64: %v", err)
					return NewErrorResponse("create", requestID, ErrNameTypeError, "Invalid PRF salt")
				}
				salt2 = hashPRFSalt(rawSalt2)
			}

			output1, output2, err := h.ctap2Handler.ComputePRF(result.CredentialID, salt1, salt2)
			if err != nil {
				log.Printf("WebAuthn Create: PRF computation error: %v", err)
				return NewErrorResponse("create", requestID, ErrNameUnknown, "PRF computation failed")
			}

			prfResult.Results = &PRFOutputs{
				First: base64.StdEncoding.EncodeToString(output1),
			}
			if output2 != nil {
				prfResult.Results.Second = base64.StdEncoding.EncodeToString(output2)
			}

			log.Printf("WebAuthn Create: PRF outputs computed successfully")
		}
	}

	// Build the response
	credentialID := result.CredentialID
	response := &CreateResponse{
		Type:      "create",
		RequestID: requestID,
		Success:   true,
		Credential: &Credential{
			ID:                      base64.RawURLEncoding.EncodeToString(credentialID),
			RawID:                   base64.StdEncoding.EncodeToString(credentialID),
			Type:                    "public-key",
			AuthenticatorAttachment: "platform",
			Response: AttestationResponse{
				ClientDataJSON:    base64.StdEncoding.EncodeToString(clientDataJSON),
				AttestationObject: base64.StdEncoding.EncodeToString(result.AttestationObject),
				Transports:        []string{"internal"},
			},
			ClientExtensionResults: ClientExtensionResults{
				PRF: prfResult,
			},
		},
	}

	log.Printf("WebAuthn Create: Success, credentialID=%d bytes", len(credentialID))
	return response
}

// handleGet handles navigator.credentials.get() requests
func (h *Handler) handleGet(ctx context.Context, requestID, origin string, optionsRaw json.RawMessage) interface{} {
	// Parse get options
	var options GetOptions
	if err := json.Unmarshal(optionsRaw, &options); err != nil {
		log.Printf("WebAuthn Get: Failed to parse options: %v", err)
		return NewErrorResponse("get", requestID, ErrNameTypeError, "Invalid get options")
	}

	// H2: Validate RP ID is a registrable domain suffix of the origin
	if err := validateRPID(origin, options.RPID); err != nil {
		log.Printf("WebAuthn Get: RP ID validation failed: %v", err)
		return NewErrorResponse("get", requestID, ErrNameTypeError, "RP ID does not match origin")
	}

	// Decode challenge
	challenge, err := base64.StdEncoding.DecodeString(options.Challenge)
	if err != nil {
		log.Printf("WebAuthn Get: Failed to decode challenge: %v", err)
		return NewErrorResponse("get", requestID, ErrNameTypeError, "Invalid challenge encoding")
	}

	// Build clientDataJSON
	clientDataJSON, err := BuildClientDataJSON(ClientDataTypeGet, challenge, origin)
	if err != nil {
		log.Printf("WebAuthn Get: Failed to build clientDataJSON: %v", err)
		return NewErrorResponse("get", requestID, ErrNameUnknown, "Failed to build client data")
	}
	clientDataHash := ClientDataHash(clientDataJSON)

	// Decode allow credentials
	allowCredentials := make([][]byte, 0, len(options.AllowCredentials))
	for _, cred := range options.AllowCredentials {
		credID, err := base64.StdEncoding.DecodeString(cred.ID)
		if err != nil {
			continue
		}
		allowCredentials = append(allowCredentials, credID)
	}

	// Request user presence
	var challengeParam, appParam [32]byte
	copy(challengeParam[:], clientDataHash[:])
	rpIDHash := ctap2.HashRPID(options.RPID)
	copy(appParam[:], rpIDHash[:])

	presence := h.ctap2Handler.Presence()
	resultCh, err := presence.ConfirmPresence("Sign in to "+options.RPID, challengeParam, appParam)
	if err != nil {
		log.Printf("WebAuthn Get: User presence error: %v", err)
		return MapErrorToResponse("get", requestID, ErrUserDenied)
	}

	// Get timeout from options or use default
	timeout := 60 * time.Second
	if options.Timeout > 0 {
		timeout = time.Duration(options.Timeout) * time.Millisecond
	}

	// Wait for user presence
	childCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	select {
	case result := <-resultCh:
		if !result.OK {
			log.Printf("WebAuthn Get: User denied or error: %v", result.Error)
			if result.Error != nil && result.Error.Error() == "fingerprint verification timed out" {
				return MapErrorToResponse("get", requestID, ErrTimeout)
			}
			return MapErrorToResponse("get", requestID, ErrUserDenied)
		}
	case <-childCtx.Done():
		log.Printf("WebAuthn Get: User presence timeout")
		return MapErrorToResponse("get", requestID, ErrTimeout)
	}

	// For PRF during get, we need to use the hmac-secret CTAP2 extension
	// which requires ECDH. For now, we'll pass through the PRF extension
	// The browser extension would need to handle the ECDH key exchange
	var hmacSecretInput interface{}
	// Note: PRF during get requires ECDH key exchange which the extension handles
	// For now, we don't process PRF during get in the same way as create

	// Get the assertion
	params := &ctap2.GetAssertionParams{
		ClientDataHash:   clientDataHash[:],
		RPID:             options.RPID,
		AllowCredentials: allowCredentials,
		HmacSecretInput:  hmacSecretInput,
	}

	result, err := h.ctap2Handler.GetAssertionDirect(ctx, params)
	if err != nil {
		log.Printf("WebAuthn Get: GetAssertion error: %v", err)
		if errors.Is(err, ctap2.ErrNoCredentials) {
			return MapErrorToResponse("get", requestID, ErrNoCredentials)
		}
		return MapErrorToResponse("get", requestID, err)
	}

	// Build user handle for response
	var userHandle *string
	if len(result.UserHandle) > 0 {
		uh := base64.StdEncoding.EncodeToString(result.UserHandle)
		userHandle = &uh
	}

	// Build PRF result if hmac-secret output was returned
	var prfResult *PRFResult
	if len(result.HmacSecretOutput) > 0 {
		// The hmac-secret output is encrypted, we'd need to decrypt it
		// This is handled by the extension in a full implementation
		log.Printf("WebAuthn Get: hmac-secret output available")
	}

	// Build the response
	credentialID := result.CredentialID
	response := &GetResponse{
		Type:      "get",
		RequestID: requestID,
		Success:   true,
		Credential: &Credential{
			ID:                      base64.RawURLEncoding.EncodeToString(credentialID),
			RawID:                   base64.StdEncoding.EncodeToString(credentialID),
			Type:                    "public-key",
			AuthenticatorAttachment: "platform",
			Response: AssertionResponse{
				ClientDataJSON:    base64.StdEncoding.EncodeToString(clientDataJSON),
				AuthenticatorData: base64.StdEncoding.EncodeToString(result.AuthenticatorData),
				Signature:         base64.StdEncoding.EncodeToString(result.Signature),
				UserHandle:        userHandle,
			},
			ClientExtensionResults: ClientExtensionResults{
				PRF: prfResult,
			},
		},
	}

	log.Printf("WebAuthn Get: Success, credentialID=%d bytes", len(credentialID))
	return response
}
