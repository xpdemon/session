package key

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
)

func Generate() string {
	// Taille de la clé (en octets). 32 octets = 256 bits, c’est déjà une bonne sécurité.
	const keySize = 32

	key := make([]byte, keySize)
	_, err := io.ReadFull(rand.Reader, key)
	if err != nil {
		fmt.Printf("Erreur lors de la génération de la clé: %v\n", err)
		os.Exit(1)
	}

	// Encodage base64 pour stockage plus facile
	keyBase64 := base64.RawURLEncoding.EncodeToString(key)
	fmt.Println("Clé secrète générée")

	return keyBase64
}
