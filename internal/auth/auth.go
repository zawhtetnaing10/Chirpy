package auth

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// Hash the password
func HashPassword(password string) (string, error) {

	// If the given password is empty, return an error
	if len(password) == 0 {
		return "", fmt.Errorf("the password must not be empty")
	}

	// Hash the password
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	// Return the hashed password
	return string(hashedBytes), nil
}

// Check the password hash
func CheckPasswordHash(hash, password string) error {
	if len(hash) == 0 {
		return fmt.Errorf("the input hash is empty")
	}
	if len(password) == 0 {
		return fmt.Errorf("the given password is empty")
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}
