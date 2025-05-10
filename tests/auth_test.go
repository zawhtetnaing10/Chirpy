package tests

import (
	"testing"

	"github.com/zawhtetnaing10/Chirpy/internal/auth"
)

func TestHashPassword(t *testing.T) {
	password := "simplepassword"
	_, err := auth.HashPassword(password)
	if err != nil {
		t.Errorf("Error hashing the password : %v", err)
	}

	emptyPassword := ""
	_, emptyPassErr := auth.HashPassword(emptyPassword)
	if emptyPassErr == nil {
		t.Errorf("an error must be returned for an empty password")
	}
}

func TestCheckPasswordHash(t *testing.T) {
	password := "simplepassword"
	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Errorf("Error hashing the password : %v", err)
	}

	if checkErr := auth.CheckPasswordHash(hash, password); checkErr != nil {
		t.Errorf("Error checking password and hash")
	}
}
