package kbsclient

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// adminTokenExpirySecs matches the kbs-client default of 2 hours.
const adminTokenExpirySecs = 7200

// adminRole is the role claim expected by the KBS v0.21.0 admin authorization
// framework. The generated kbs-config maps this role to all /kbs endpoints via
// [admin.authorization.regex_acl].
const adminRole = "admin"

type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type jwtClaims struct {
	Role string `json:"role"`
	Iat  int64  `json:"iat"`
	Exp  int64  `json:"exp"`
}

// signAdminToken creates a JWT signed with the given Ed25519 private key.
// The token carries the "admin" role plus iat/exp claims. KBS v0.21.0
// requires the role claim to authorize admin endpoints via its regex ACL.
func signAdminToken(privateKey ed25519.PrivateKey) (string, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("invalid Ed25519 private key: got %d bytes, want %d", len(privateKey), ed25519.PrivateKeySize)
	}

	header := jwtHeader{Alg: "EdDSA", Typ: "JWT"}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshal JWT header: %w", err)
	}

	now := time.Now().Unix()
	claims := jwtClaims{
		Role: adminRole,
		Iat:  now,
		Exp:  now + adminTokenExpirySecs,
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal JWT claims: %w", err)
	}

	headerEncoded := base64urlEncode(headerJSON)
	claimsEncoded := base64urlEncode(claimsJSON)
	signingInput := headerEncoded + "." + claimsEncoded

	sig := ed25519.Sign(privateKey, []byte(signingInput))

	return signingInput + "." + base64urlEncode(sig), nil
}

// base64urlEncode encodes data using base64 URL encoding without padding.
func base64urlEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}
