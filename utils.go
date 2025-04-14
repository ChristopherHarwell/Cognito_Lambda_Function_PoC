package main

import (
	"crypto/rand"
	"encoding/base64"
	"math/big"
)

// GenerateRandomString generates a random string of specified length
// The length must be between minLength and maxLength (inclusive)
func GenerateRandomString(minLength, maxLength int) (string, error) {
	if minLength < 1 || maxLength < minLength {
		return "", nil
	}

	// Generate a random length between minLength and maxLength
	lengthRange := big.NewInt(int64(maxLength - minLength + 1))
	randomLength, err := rand.Int(rand.Reader, lengthRange)
	if err != nil {
		return "", err
	}
	length := int(randomLength.Int64()) + minLength

	// Generate random bytes
	bytes := make([]byte, length)
	_, err = rand.Read(bytes)
	if err != nil {
		return "", err
	}

	// Convert to base64 string and trim to desired length
	randomString := base64.URLEncoding.EncodeToString(bytes)
	return randomString[:length], nil
}
