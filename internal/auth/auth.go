package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"net/http"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/zawhtetnaing10/Chirpy/constants"
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

// Make JWT
func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {

	// Check if user id is nil
	if userID == uuid.Nil {
		return "", fmt.Errorf("the user id must not be nil")
	}

	// new jwt
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    "chirpy",
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiresIn)),
		Subject:   userID.String(),
	})

	// Sign the token
	signedToken, err := token.SignedString([]byte(tokenSecret))
	if err != nil {
		return "", fmt.Errorf("cannot sign key: %w", err)
	}

	// Return the signed token
	return signedToken, nil
}

// Validate JWT
func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	// Verify tokenString and get token
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return uuid.Nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Returned the secret key for token
		return []byte(tokenSecret), nil
	})
	if err != nil {
		return uuid.Nil, err
	}

	// Extract user id from token
	userId, userIdErr := token.Claims.GetSubject()
	if userIdErr != nil {
		return uuid.Nil, userIdErr
	}

	// Return the parsed user Id
	userUuid, parseErr := uuid.Parse(userId)
	if parseErr != nil {
		return uuid.Nil, fmt.Errorf("error parsing user id : %w", parseErr)
	}
	return userUuid, nil
}

// Get Api Key
func GetApiKey(headers http.Header) (string, error) {
	// Get api key
	authHeader := headers.Get(constants.AUTHORIZATION)
	// Api Key must not be empty
	if authHeader == "" {
		return "", errors.New("the api key must not be empty")
	}

	// Remove prefix ApiKey
	apiKey := strings.TrimPrefix(authHeader, constants.API_KEY)

	// user sends in only ApiKey with no value
	if apiKey == authHeader {
		return "", errors.New("invalid api key format. The correct format is ApiKey {apiKey}")
	}

	// Check for empty token
	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		return "", errors.New("the api key must not be empty")
	}

	return apiKey, nil
}

// Get Bearer Token
func GetBearerToken(headers http.Header) (string, error) {
	// Get bearer token
	authHeader := headers.Get(constants.AUTHORIZATION)
	// Auth token must not be empty
	if authHeader == "" {
		return "", errors.New("the auth token must not be empty")
	}

	// Remove prefix Bearer
	tokenString := strings.TrimPrefix(authHeader, constants.BEAERER)

	// user sends in only Bearer with no token string
	if tokenString == authHeader {
		return "", errors.New("invalid bearer token format. The correct format is Bearer {token}")
	}

	// Check for empty token
	tokenString = strings.TrimSpace(tokenString)
	if tokenString == "" {
		return "", errors.New("the token string must not be empty")
	}

	return tokenString, nil
}

// Make refresh token
func MakeRefreshToken() (string, error) {
	numBytes := 32
	randomBytes := make([]byte, numBytes)

	n, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}
	if n != numBytes {
		return "", fmt.Errorf("read %d bytes, expected %d", n, numBytes)
	}

	return hex.EncodeToString(randomBytes), nil
}
