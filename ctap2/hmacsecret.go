package ctap2

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"math/big"

	"github.com/fxamacker/cbor/v2"
)

// processHmacSecret processes the hmac-secret extension for GetAssertion
// It takes the credential ID and the hmac-secret input from the request,
// performs the ECDH key exchange, decrypts the salts, and returns the encrypted output
func (h *Handler) processHmacSecret(credentialID []byte, hmacSecretRaw interface{}) ([]byte, error) {
	// Parse the hmac-secret input
	// It can come as a map[interface{}]interface{} from CBOR
	rawBytes, err := cbor.Marshal(hmacSecretRaw)
	if err != nil {
		return nil, fmt.Errorf("failed to re-marshal hmac-secret input: %w", err)
	}

	var input HmacSecretInput
	if err := cbor.Unmarshal(rawBytes, &input); err != nil {
		return nil, fmt.Errorf("failed to parse hmac-secret input: %w", err)
	}

	log.Printf("CTAP2 hmac-secret: KeyAgreement kty=%d, crv=%d, X len=%d, Y len=%d",
		input.KeyAgreement.Kty, input.KeyAgreement.Crv,
		len(input.KeyAgreement.X), len(input.KeyAgreement.Y))
	log.Printf("CTAP2 hmac-secret: saltEnc len=%d, saltAuth len=%d",
		len(input.SaltEnc), len(input.SaltAuth))

	// Validate key agreement parameters
	if input.KeyAgreement.Kty != COSEKeyTypeEC2 {
		return nil, errors.New("invalid key type, expected EC2")
	}
	if input.KeyAgreement.Crv != COSECurveP256 {
		return nil, errors.New("invalid curve, expected P-256")
	}

	// Get platform's public key from COSE format
	curve := elliptic.P256()
	x := new(big.Int).SetBytes(input.KeyAgreement.X)
	y := new(big.Int).SetBytes(input.KeyAgreement.Y)

	// H4: Validate that the public key point is on the P-256 curve
	// to prevent invalid curve attacks
	if !curve.IsOnCurve(x, y) {
		return nil, errors.New("invalid ECDH public key: point is not on the P-256 curve")
	}

	platformPubKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	// Perform ECDH using our ephemeral private key
	if h.ecdhKey == nil {
		return nil, errors.New("no ECDH key available")
	}

	// ECDH: compute shared point
	sharedX, _ := platformPubKey.Curve.ScalarMult(platformPubKey.X, platformPubKey.Y, h.ecdhKey.D.Bytes())

	// Shared secret = SHA256(sharedX)
	sharedSecret := sha256.Sum256(padTo32(sharedX.Bytes()))

	log.Printf("CTAP2 hmac-secret: computed shared secret")

	// Verify saltAuth: HMAC-SHA256(sharedSecret, saltEnc)[:16]
	mac := hmac.New(sha256.New, sharedSecret[:])
	mac.Write(input.SaltEnc)
	expectedSaltAuth := mac.Sum(nil)[:16]

	if !hmac.Equal(input.SaltAuth, expectedSaltAuth) {
		log.Printf("CTAP2 hmac-secret: saltAuth verification failed")
		return nil, errors.New("saltAuth verification failed")
	}

	log.Printf("CTAP2 hmac-secret: saltAuth verified")

	// Decrypt salts: AES-256-CBC with IV=0
	block, err := aes.NewCipher(sharedSecret[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	iv := make([]byte, aes.BlockSize) // All zeros
	mode := cipher.NewCBCDecrypter(block, iv)

	salts := make([]byte, len(input.SaltEnc))
	mode.CryptBlocks(salts, input.SaltEnc)

	log.Printf("CTAP2 hmac-secret: decrypted salts, len=%d", len(salts))

	// Get credential random: derived from master secret and credential ID
	credRandom, err := h.signer.DeriveCredRandom(credentialID)
	if err != nil {
		return nil, fmt.Errorf("failed to derive credential random: %w", err)
	}

	// Compute output(s)
	// Salt can be 32 bytes (one salt) or 64 bytes (two salts)
	var output []byte

	if len(salts) == 32 {
		// Single salt
		hmacOut := hmac.New(sha256.New, credRandom)
		hmacOut.Write(salts)
		output = hmacOut.Sum(nil)
	} else if len(salts) == 64 {
		// Two salts
		hmacOut1 := hmac.New(sha256.New, credRandom)
		hmacOut1.Write(salts[:32])
		output1 := hmacOut1.Sum(nil)

		hmacOut2 := hmac.New(sha256.New, credRandom)
		hmacOut2.Write(salts[32:])
		output2 := hmacOut2.Sum(nil)

		output = append(output1, output2...)
	} else {
		return nil, fmt.Errorf("invalid salt length: %d (expected 32 or 64)", len(salts))
	}

	log.Printf("CTAP2 hmac-secret: computed output, len=%d", len(output))

	// Encrypt output: AES-256-CBC with IV=0
	encrypter := cipher.NewCBCEncrypter(block, iv)
	encryptedOutput := make([]byte, len(output))
	encrypter.CryptBlocks(encryptedOutput, output)

	log.Printf("CTAP2 hmac-secret: encrypted output, len=%d", len(encryptedOutput))

	return encryptedOutput, nil
}

// GenerateECDHKey generates a new ephemeral ECDH key pair
func (h *Handler) GenerateECDHKey() error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate ECDH key: %w", err)
	}
	h.ecdhKey = key
	log.Printf("CTAP2: Generated new ECDH key")
	return nil
}

// GetECDHPublicKey returns the ECDH public key in COSE format
func (h *Handler) GetECDHPublicKey() (*COSEKey, error) {
	if h.ecdhKey == nil {
		if err := h.GenerateECDHKey(); err != nil {
			return nil, err
		}
	}

	return &COSEKey{
		Kty: COSEKeyTypeEC2,
		Alg: COSEAlgECDH,
		Crv: COSECurveP256,
		X:   padTo32(h.ecdhKey.X.Bytes()),
		Y:   padTo32(h.ecdhKey.Y.Bytes()),
	}, nil
}

// ComputePRF computes PRF outputs directly for a credential.
// This is used for PRF-during-create where we control both ends and don't need ECDH.
// salt1 and salt2 should be 32 bytes each (salt2 is optional).
func (h *Handler) ComputePRF(credentialID, salt1, salt2 []byte) (output1, output2 []byte, err error) {
	// Get credential random from signer
	credRandom, err := h.signer.DeriveCredRandom(credentialID)
	if err != nil {
		return nil, nil, err
	}

	// Compute HMAC-SHA256(credRandom, salt1)
	hmacOut1 := hmac.New(sha256.New, credRandom)
	hmacOut1.Write(salt1)
	output1 = hmacOut1.Sum(nil)

	// Compute HMAC-SHA256(credRandom, salt2) if provided
	if len(salt2) > 0 {
		hmacOut2 := hmac.New(sha256.New, credRandom)
		hmacOut2.Write(salt2)
		output2 = hmacOut2.Sum(nil)
	}

	return output1, output2, nil
}
