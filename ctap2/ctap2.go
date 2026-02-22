package ctap2

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"log"
	"math/big"

	"github.com/fxamacker/cbor/v2"
	"github.com/psanford/tpm-fido/userpresence"
)

// Signer is the interface that the TPM or memory backend must implement
type Signer interface {
	RegisterKey(applicationParam []byte) ([]byte, *big.Int, *big.Int, error)
	SignASN1(keyHandle, applicationParam, digest []byte) ([]byte, error)
	Counter() uint32
	DeriveCredRandom(credentialID []byte) ([]byte, error)
}

// MakeCredentialResult contains the result of a successful MakeCredential operation
type MakeCredentialResult struct {
	CredentialID      []byte
	AttestationObject []byte // CBOR-encoded attestation object (for WebAuthn response)
	AuthData          []byte // Raw authenticator data bytes
	PublicKeyX        *big.Int
	PublicKeyY        *big.Int
	HmacSecretEnabled bool
}

// GetAssertionResult contains the result of a successful GetAssertion operation
type GetAssertionResult struct {
	CredentialID      []byte
	AuthenticatorData []byte
	Signature         []byte
	UserHandle        []byte // For discoverable credentials
	UserName          string // For discoverable credentials
	UserDisplayName   string // For discoverable credentials
	HmacSecretOutput  []byte // Encrypted hmac-secret output if extension was processed
}

// Common errors for Native Messaging
var (
	ErrCredentialExcluded  = errors.New("credential already registered")
	ErrNoCredentials       = errors.New("no credentials found")
	ErrUserDenied          = errors.New("user denied the request")
	ErrTimeout             = errors.New("operation timed out")
	ErrUnsupportedAlgorithm = errors.New("unsupported algorithm")
	ErrInvalidParameter    = errors.New("invalid parameter")
)

// Handler handles CTAP2 commands
type Handler struct {
	signer   Signer
	presence *userpresence.UserPresence
	storage  *CredentialStorage
	aaguid   [16]byte
	ecdhKey  *ecdsa.PrivateKey // Ephemeral key for hmac-secret

	// IsPlatform controls GetInfo response:
	//   true  = platform authenticator (plat=true, transports=["internal"])
	//   false = roaming authenticator via HID (plat=false, transports=["usb"])
	IsPlatform bool

	// State for GetNextAssertion
	assertionState *assertionState
}

// assertionState holds state between GetAssertion and GetNextAssertion calls
type assertionState struct {
	credentials     []*CredentialMetadata
	currentIndex    int
	rpIDHash        [32]byte
	clientDataHash  []byte
	extensionsInput map[string]interface{}
}

// NewHandler creates a new CTAP2 command handler
func NewHandler(signer Signer, presence *userpresence.UserPresence, storage *CredentialStorage) *Handler {
	// Generate AAGUID from SHA256("tpm-fido-prf")[:16]
	hash := sha256.Sum256([]byte("tpm-fido-prf"))
	var aaguid [16]byte
	copy(aaguid[:], hash[:16])

	return &Handler{
		signer:   signer,
		presence: presence,
		storage:  storage,
		aaguid:   aaguid,
	}
}

// Signer returns the signer backend for direct access (used for PRF-during-create)
func (h *Handler) Signer() Signer {
	return h.signer
}

// Presence returns the user presence handler
func (h *Handler) Presence() *userpresence.UserPresence {
	return h.presence
}

// Storage returns the credential storage
func (h *Handler) Storage() *CredentialStorage {
	return h.storage
}

// AAGUID returns the authenticator's AAGUID
func (h *Handler) AAGUID() [16]byte {
	return h.aaguid
}

// HandleCommand dispatches a CTAP2 command and returns the status and response
func (h *Handler) HandleCommand(ctx context.Context, cmd byte, data []byte) (status byte, response []byte) {
	log.Printf("CTAP2: Received command 0x%02x, data len=%d", cmd, len(data))

	switch cmd {
	case CmdGetInfo:
		return h.handleGetInfo(ctx)
	case CmdMakeCredential:
		return h.handleMakeCredential(ctx, data)
	case CmdGetAssertion:
		return h.handleGetAssertion(ctx, data)
	case CmdGetNextAssertion:
		return h.handleGetNextAssertion(ctx)
	case CmdClientPIN:
		return h.handleClientPIN(ctx, data)
	default:
		log.Printf("CTAP2: Unknown command 0x%02x", cmd)
		return StatusInvalidCommand, nil
	}
}

// CTAP2 requires canonical CBOR encoding with sorted map keys
var ctapEncMode, _ = cbor.EncOptions{
	Sort: cbor.SortCanonical,
}.EncMode()

// handleGetInfo handles authenticatorGetInfo (0x04)
func (h *Handler) handleGetInfo(ctx context.Context) (byte, []byte) {
	resp := h.GetInfo()

	encoded, err := ctapEncMode.Marshal(resp)
	if err != nil {
		log.Printf("CTAP2 GetInfo: CBOR encode error: %s", err)
		return StatusOther, nil
	}

	log.Printf("CTAP2 GetInfo: Response encoded, %d bytes", len(encoded))
	return StatusSuccess, encoded
}

// handleMakeCredential handles authenticatorMakeCredential (0x01)
func (h *Handler) handleMakeCredential(ctx context.Context, data []byte) (byte, []byte) {
	req, err := parseMakeCredentialRequest(data)
	if err != nil {
		log.Printf("CTAP2 MakeCredential: CBOR decode error: %s", err)
		return StatusInvalidCBOR, nil
	}

	return h.MakeCredential(ctx, req)
}

// handleGetAssertion handles authenticatorGetAssertion (0x02)
func (h *Handler) handleGetAssertion(ctx context.Context, data []byte) (byte, []byte) {
	req, err := parseGetAssertionRequest(data)
	if err != nil {
		log.Printf("CTAP2 GetAssertion: CBOR decode error: %s", err)
		return StatusInvalidCBOR, nil
	}

	return h.GetAssertion(ctx, req)
}

// handleClientPIN handles authenticatorClientPIN (0x06)
func (h *Handler) handleClientPIN(ctx context.Context, data []byte) (byte, []byte) {
	// Parse the request to get the subcommand
	var req ClientPINRequest
	if err := cbor.Unmarshal(data, &req); err != nil {
		log.Printf("CTAP2 ClientPIN: CBOR decode error: %s", err)
		return StatusInvalidCBOR, nil
	}

	log.Printf("CTAP2 ClientPIN: subcommand=%d", req.SubCommand)

	switch req.SubCommand {
	case ClientPINSubCmdGetKeyAgreement:
		return h.handleGetKeyAgreement(ctx, &req)
	default:
		// For now, return PIN not set for most subcommands
		// This is expected behavior for an authenticator without PIN
		log.Printf("CTAP2 ClientPIN: Subcommand %d not implemented", req.SubCommand)
		return StatusPINNotSet, nil
	}
}

// handleGetKeyAgreement handles ClientPIN getKeyAgreement subcommand
func (h *Handler) handleGetKeyAgreement(ctx context.Context, req *ClientPINRequest) (byte, []byte) {
	log.Printf("CTAP2 ClientPIN GetKeyAgreement: Generating ECDH key")

	// Generate a new ECDH key pair
	pubKey, err := h.GetECDHPublicKey()
	if err != nil {
		log.Printf("CTAP2 ClientPIN GetKeyAgreement: Key generation error: %s", err)
		return StatusOther, nil
	}

	resp := &ClientPINResponse{
		KeyAgreement: pubKey,
	}

	encoded, err := ctapEncMode.Marshal(resp)
	if err != nil {
		log.Printf("CTAP2 ClientPIN GetKeyAgreement: Response encode error: %s", err)
		return StatusOther, nil
	}

	log.Printf("CTAP2 ClientPIN GetKeyAgreement: Success, response=%d bytes", len(encoded))
	return StatusSuccess, encoded
}

// handleGetNextAssertion handles authenticatorGetNextAssertion (0x08)
// Returns the next credential from a previous GetAssertion that returned multiple matches
func (h *Handler) handleGetNextAssertion(ctx context.Context) (byte, []byte) {
	log.Printf("CTAP2 GetNextAssertion: called")

	if h.assertionState == nil {
		log.Printf("CTAP2 GetNextAssertion: No active assertion state")
		return StatusNotAllowed, nil
	}

	state := h.assertionState
	state.currentIndex++

	if state.currentIndex >= len(state.credentials) {
		log.Printf("CTAP2 GetNextAssertion: No more credentials (index=%d, total=%d)", state.currentIndex, len(state.credentials))
		h.assertionState = nil
		return StatusNotAllowed, nil
	}

	cred := state.credentials[state.currentIndex]
	log.Printf("CTAP2 GetNextAssertion: Returning credential %d of %d for RP=%s", state.currentIndex+1, len(state.credentials), cred.RPID)

	// Build the assertion response for this credential
	return h.buildAssertionResponse(ctx, cred, state.rpIDHash, state.clientDataHash, state.extensionsInput, len(state.credentials), false)
}
