package tests

import (
	"testing"
	"time"

	"github.com/google/uuid"
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

func TestMakeJWT(t *testing.T) {
	userId, _ := uuid.Parse("1e5d7346-6ab1-4627-9e90-4cfe531361bb")
	tokenSecret := "rT8!pL3#vQ7@kF9$mZ2&xY5*wC1^"
	_, err := auth.MakeJWT(userId, tokenSecret, 2)
	if err != nil {
		t.Errorf("Error creating jwt token: %v", err)
	}
}

func TestValidateJWTPositive(t *testing.T) {
	// Make jwt token
	userId, _ := uuid.Parse("1e5d7346-6ab1-4627-9e90-4cfe531361bb")
	tokenSecret := "rT8!pL3#vQ7@kF9$mZ2&xY5*wC1^"
	jwtTokenString, err := auth.MakeJWT(userId, tokenSecret, 2*time.Minute)
	if err != nil {
		t.Errorf("Error creating jwt token: %v", err)
	}

	// Normal validation
	_, validateErr := auth.ValidateJWT(jwtTokenString, tokenSecret)
	if validateErr != nil {
		t.Errorf("Error validating jwt token %v", validateErr)
	}
}

func TestValidateJWTWrongSecret(t *testing.T) {
	// Make jwt token
	userId, _ := uuid.Parse("1e5d7346-6ab1-4627-9e90-4cfe531361bb")
	tokenSecret := "rT8!pL3#vQ7@kF9$mZ2&xY5*wC1^"
	jwtTokenString, err := auth.MakeJWT(userId, tokenSecret, 2*time.Minute)
	if err != nil {
		t.Errorf("Error creating jwt token: %v", err)
	}

	// Validate with wrong secret
	wrongSecret := "kafjlafdasdfjlajsfjalk"
	_, validateErr := auth.ValidateJWT(jwtTokenString, wrongSecret)
	if validateErr == nil {
		t.Errorf("There must be an error returned for wrong secret")
	}
}

func TestValidateJWTTokenExpired(t *testing.T) {
	// Make jwt token
	userId, _ := uuid.Parse("1e5d7346-6ab1-4627-9e90-4cfe531361bb")
	tokenSecret := "rT8!pL3#vQ7@kF9$mZ2&xY5*wC1^"
	jwtTokenString, err := auth.MakeJWT(userId, tokenSecret, 2*time.Second)
	if err != nil {
		t.Errorf("Error creating jwt token: %v", err)
	}

	// Sleep for 3 secs to expire the token
	time.Sleep(3 * time.Second)

	// Validate with wrong secret
	_, validateErr := auth.ValidateJWT(jwtTokenString, tokenSecret)
	if validateErr == nil {
		t.Errorf("There must be an error returned for token expire")
	}
}

func TestValidateJWTInvalidFormat(t *testing.T) {
	// Token with invalid format
	invalidToken := "not.a.jwt"
	tokenSecret := "rT8!pL3#vQ7@kF9$mZ2&xY5*wC1^"

	// Validate the invalid jwt
	_, validateErr := auth.ValidateJWT(invalidToken, tokenSecret)
	if validateErr == nil {
		t.Errorf("There must be an error returned for invalid token format")
	}
}
