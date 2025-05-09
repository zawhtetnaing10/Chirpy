package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"fmt"
	"strings"

	"sync/atomic"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/zawhtetnaing10/Chirpy/constants"

	"github.com/zawhtetnaing10/Chirpy/internal/database"
)

// In memory data
type ApiConfig struct {
	Platform       string
	FileServerHits atomic.Int32
	Db             *database.Queries
}

// User response
type UserResponse struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Email     string    `json:"email"`
}

// Chirp Response
type ChirpResponse struct {
	ID        uuid.UUID     `json:"id"`
	CreatedAt time.Time     `json:"created_at"`
	UpdatedAt time.Time     `json:"updated_at"`
	Body      string        `json:"body"`
	UserID    uuid.NullUUID `json:"user_id"`
}

// Readiness handler
func ReadinessHandler(writer http.ResponseWriter, request *http.Request) {
	// Set content type in header
	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	// Set status code
	writer.WriteHeader(http.StatusOK)
	// Set response
	writer.Write([]byte("OK"))
}

// Middleware to increase request count
func (cfg *ApiConfig) MiddlewareMetricsInc(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		cfg.FileServerHits.Add(1)
		handler.ServeHTTP(writer, request)
	})
}

// Get Chirp
func (cfg *ApiConfig) GetChirp(writer http.ResponseWriter, request *http.Request) {
	// Get chirp_id from request
	chirpIdFromRequest := request.PathValue("chirp_id")
	// Parse the chirp_id
	chirpUUID, uuidErr := uuid.Parse(chirpIdFromRequest)
	if uuidErr != nil {
		respondWithError(writer, constants.SERVER_ERROR, uuidErr.Error())
		return
	}

	// Get chirp from db
	chirp, getChirpErr := cfg.Db.GetChirp(request.Context(), chirpUUID)
	if getChirpErr != nil {
		respondWithError(writer, constants.NOT_FOUND, "Cannot find chirp with the given id")
		return
	}

	// Chirp response
	chirpResponse := ChirpResponse{
		ID:        chirp.ID,
		CreatedAt: chirp.CreatedAt,
		UpdatedAt: chirp.UpdatedAt,
		Body:      chirp.Body,
		UserID:    chirp.UserID,
	}

	respondWithJSON(writer, constants.SUCCESS, chirpResponse)
}

// Get All Chirps
func (cfg *ApiConfig) GetAllChirps(writer http.ResponseWriter, request *http.Request) {
	// Get chirps from DB
	chirps, err := cfg.Db.GetAllChirps(request.Context())
	if err != nil {
		respondWithError(writer, constants.SERVER_ERROR, err.Error())
		return
	}

	// Convert to chirp response
	chirpsForResponse := []ChirpResponse{}
	for i := range chirps {
		chirpResponse := ChirpResponse{
			ID:        chirps[i].ID,
			CreatedAt: chirps[i].CreatedAt,
			UpdatedAt: chirps[i].UpdatedAt,
			Body:      chirps[i].Body,
			UserID:    chirps[i].UserID,
		}
		chirpsForResponse = append(chirpsForResponse, chirpResponse)
	}

	// If successful, send the response
	respondWithJSON(writer, constants.SUCCESS, chirpsForResponse)
}

// Create Chirp
func (cfg *ApiConfig) CreateChirp(writer http.ResponseWriter, request *http.Request) {
	// Read the request
	type requestParameters struct {
		Body   string `json:"body"`
		UserId string `json:"user_id"`
	}

	// Parse the request
	decoder := json.NewDecoder(request.Body)
	requestParams := requestParameters{}
	if err := decoder.Decode(&requestParams); err != nil {
		respondWithError(writer, constants.SERVER_ERROR, err.Error())
		return
	}

	parsedUserId, userIdErr := uuid.Parse(requestParams.UserId)
	if userIdErr != nil {
		respondWithError(writer, constants.SERVER_ERROR, userIdErr.Error())
		return
	}
	// Check if the user exists in db
	_, userErr := cfg.Db.GetUserById(request.Context(), parsedUserId)
	if userErr != nil {
		respondWithError(writer, constants.SERVER_ERROR, "There's no user with the given id.")
		return
	}

	// Validate Chirp
	// Take care of a case where length > 140
	if len(requestParams.Body) > 140 {
		respondWithError(writer, constants.BAD_REQUEST, "Chirp is too long")
		return
	}

	// Censor the profane words
	profaneWords := []string{"kerfuffle", "sharbert", "fornax"}
	censoredWord := "****"
	words := strings.Split(requestParams.Body, " ")
	for i := 0; i < len(words); i++ {
		for _, profaneWord := range profaneWords {
			if strings.ToLower(words[i]) == profaneWord {
				words[i] = censoredWord
			}
		}
	}
	cleanedBody := strings.Join(words, " ")

	// Parse the uuid from input
	parsedUUID, uuidErr := uuid.Parse(requestParams.UserId)
	if uuidErr != nil {
		respondWithError(writer, constants.SERVER_ERROR, uuidErr.Error())
		return
	}
	// Insert the chirp into DB
	createChirpParams := database.CreateChirpParams{
		Body: cleanedBody,
		UserID: uuid.NullUUID{
			UUID:  parsedUUID,
			Valid: true,
		},
	}
	createdChirp, createChirpErr := cfg.Db.CreateChirp(request.Context(), createChirpParams)
	if createChirpErr != nil {
		respondWithError(writer, constants.SERVER_ERROR, createChirpErr.Error())
		return
	}

	// Create response
	chirpResponse := ChirpResponse{
		ID:        createdChirp.ID,
		CreatedAt: createdChirp.CreatedAt,
		UpdatedAt: createdChirp.UpdatedAt,
		Body:      createdChirp.Body,
		UserID:    createdChirp.UserID,
	}

	// Successful response
	respondWithJSON(writer, constants.CREATED, chirpResponse)
}

// Create user
func (cfg *ApiConfig) CreateUser(writer http.ResponseWriter, request *http.Request) {
	// Read the request
	// Read input param
	type requestParameters struct {
		Email string `json:"email"`
	}

	// Get the email from request
	decoder := json.NewDecoder(request.Body)
	requestParams := requestParameters{}
	if err := decoder.Decode(&requestParams); err != nil {
		respondWithError(writer, constants.SERVER_ERROR, err.Error())
		return
	}

	// Insert user into db
	insertedUser, userInsertErr := cfg.Db.CreateUser(request.Context(), requestParams.Email)
	if userInsertErr != nil {
		respondWithError(writer, constants.SERVER_ERROR, userInsertErr.Error())
		return
	}
	// Set up user response
	userResponse := UserResponse{
		ID:        insertedUser.ID,
		CreatedAt: insertedUser.CreatedAt,
		UpdatedAt: insertedUser.UpdatedAt,
		Email:     insertedUser.Email,
	}

	// User successfully created
	respondWithJSON(writer, constants.CREATED, userResponse)
}

// Metrics Handler
func (cfg *ApiConfig) MetricsHandler(writer http.ResponseWriter, request *http.Request) {
	// Set content type in header
	writer.Header().Set(constants.CONTENT_TYPE, constants.TEXT_PLAIN)
	// Set status code
	writer.WriteHeader(http.StatusOK)

	// Set response html
	responseString := fmt.Sprintf(`
	<html>
	<body>
	  <h1>Welcome, Chirpy Admin</h1>
	  <p>Chirpy has been visited %d times!</p>
	</body>
  	</html>
	`, cfg.FileServerHits.Load())
	writer.Write([]byte(responseString))
}

// Reset file server hits
func (cfg *ApiConfig) ResetHandler(writer http.ResponseWriter, request *http.Request) {
	// Convert file server hits atomic.Int32 back to zero
	cfg.FileServerHits.Store(0)

	if cfg.Platform == constants.DEV {
		// Dev env. Can delete users
		userDeleteErr := cfg.Db.DeleteAllUsers(request.Context())
		if userDeleteErr != nil {
			respondWithError(writer, constants.SERVER_ERROR, userDeleteErr.Error())
			return
		}

		chirpDeleteErr := cfg.Db.DeleteAllChirps(request.Context())
		if chirpDeleteErr != nil {
			respondWithError(writer, constants.SERVER_ERROR, chirpDeleteErr.Error())
			return
		}

		// Set successful status
		writer.WriteHeader(http.StatusOK)
	} else {
		// Prod env. Cannot delete users
		respondWithError(writer, constants.FORBIDDEN, constants.CANNOT_DELETE_USERS_IN_PROD)
		return
	}
}

// Helper function to respond with json
func respondWithJSON(writer http.ResponseWriter, code int, payload interface{}) {
	payloadData, err := json.Marshal(payload)
	if err != nil {
		respondWithError(writer, constants.SERVER_ERROR, err.Error())
		return
	}

	writer.Header().Set(constants.CONTENT_TYPE, constants.APPLICATION_JSON)
	writer.WriteHeader(code)
	writer.Write(payloadData)
}

// Helper function to respond with error
func respondWithError(writer http.ResponseWriter, code int, msg string) {
	/// Set up error struct
	type errorVals struct {
		Error string `json:"error"`
	}
	/// Construct error struct
	errStruct := errorVals{
		Error: msg,
	}

	/// Encode the error struct to data
	errData, err := json.Marshal(errStruct)
	if err != nil {
		/// If Encoding fails, sent the server error as plain text
		writer.Header().Set(constants.CONTENT_TYPE, constants.TEXT_PLAIN)
		writer.WriteHeader(500)
		writer.Write([]byte(err.Error()))
		return
	}

	/// Write the data
	writer.Header().Set(constants.CONTENT_TYPE, constants.APPLICATION_JSON)
	writer.WriteHeader(code)
	writer.Write(errData)
}
