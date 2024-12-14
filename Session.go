package session

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
)

var secretKey = []byte("DQqjm8uFWaqXmtfO4uqil-4Lf323JUxkh6V9FaIFoKo")

// GenerateId génère un ID de session aléatoire.
func GenerateSessionID(length int) (string, error) {
	// On génère length octets aléatoires
	buf := make([]byte, length)
	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		return "", err
	}

	// On encode en base64 (sans padding) pour obtenir une chaîne sûre
	id := base64.RawURLEncoding.EncodeToString(buf)
	return id, nil
}

// SignID calcule la signature HMAC d'un ID et renvoie "ID:Signature"
func SignID(sessionID string) string {
	h := hmac.New(sha256.New, secretKey)
	h.Write([]byte(sessionID))
	signature := h.Sum(nil)
	sigEncoded := base64.RawURLEncoding.EncodeToString(signature)

	// Format final : "<sessionID>:<signature>"
	return sessionID + ":" + sigEncoded
}

// ValidateSignedID vérifie la signature du session_id
func ValidateSignedID(signedValue string) (string, error) {
	parts := strings.Split(signedValue, ":")
	if len(parts) != 2 {
		return "", fmt.Errorf("format session invalide")
	}

	sessionID := parts[0]
	sig := parts[1]

	// Décodage de la signature
	signature, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return "", fmt.Errorf("signature base64 invalide")
	}

	// Recalcul de la signature
	h := hmac.New(sha256.New, secretKey)
	h.Write([]byte(sessionID))
	expectedSig := h.Sum(nil)

	// Compare les signatures en "constant time" pour éviter les attaques timing
	if !hmac.Equal(signature, expectedSig) {
		return "", fmt.Errorf("signature invalide")
	}

	// Signature valide, retourne le sessionID
	return sessionID, nil
}
