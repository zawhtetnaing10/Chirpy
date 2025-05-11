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
	"github.com/zawhtetnaing10/Chirpy/utils"

	"github.com/zawhtetnaing10/Chirpy/internal/auth"
	"github.com/zawhtetnaing10/Chirpy/internal/database"
)

// In memory data
type ApiConfig struct {
	Platform       string
	FileServerHits atomic.Int32
	TokenSecret    string
	Db             *database.Queries
}

// Requests
// Email and Password
type EmailAndPasswordRequest struct {
	Password string `json:"password"`
	Email    string `json:"email"`
}

// Upgrade Chirpy Red
type UpgradeChirpyRedRequest struct {
	Event string        `json:"event"`
	Data  ChirpyRedData `json:"data"`
}

type ChirpyRedData struct {
	UserId string `json:"user_id"`
}

// Refresh token response
type RefreshTokenResponse struct {
	Token string `json:"token"`
}

// Response for login
type LoginResponse struct {
	ID           uuid.UUID `json:"id"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Email        string    `json:"email"`
	Token        string    `json:"token"`
	RefreshToken string    `json:"refresh_token"`
	IsChirpyRed  bool      `json:"is_chirpy_red"`
}

// User response
type UserResponse struct {
	ID          uuid.UUID `json:"id"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Email       string    `json:"email"`
	IsChirpyRed bool      `json:"is_chirpy_red"`
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

// Get email and password from request
func getEmailAndPasswordFromRequest(request *http.Request) (EmailAndPasswordRequest, error) {
	// Get the email from request
	decoder := json.NewDecoder(request.Body)
	requestParams := EmailAndPasswordRequest{}
	if err := decoder.Decode(&requestParams); err != nil {
		return EmailAndPasswordRequest{}, err
	}

	return requestParams, nil
}

// Get user id from auth token
func (cfg *ApiConfig) getUserIdFromAuthToken(header http.Header) (uuid.UUID, error) {
	// Get the auth token from header
	authToken, authTokenErr := auth.GetBearerToken(header)
	if authTokenErr != nil {
		return uuid.Nil, authTokenErr
	}

	// Validate token and get the user_id
	userId, validateJWTErr := auth.ValidateJWT(authToken, cfg.TokenSecret)
	if validateJWTErr != nil {
		return uuid.Nil, validateJWTErr
	}

	// If successful return the user id
	return userId, nil
}

// Upgrade Chirpy Red
func (cfg *ApiConfig) UpgradeChirpyRed(writer http.ResponseWriter, request *http.Request) {
	// Parse the request
	decoder := json.NewDecoder(request.Body)
	requestParams := UpgradeChirpyRedRequest{}
	if reqErr := decoder.Decode(&requestParams); reqErr != nil {
		respondWithError(writer, constants.BAD_REQUEST, reqErr.Error())
		return
	}

	// If the event is not user.upgraded immediately return 204 no content
	if requestParams.Event != constants.UPGRADE_CHIRPY_RED_EVENT {
		writer.WriteHeader(constants.NO_CONTENT)
		return
	}

	// Parse the uuid
	parsedUserId, uuidErr := uuid.Parse(requestParams.Data.UserId)
	if uuidErr != nil {
		respondWithError(writer, constants.SERVER_ERROR, uuidErr.Error())
		return
	}

	// Get User from Db
	userInDb, getErr := cfg.Db.GetUserById(request.Context(), parsedUserId)
	if getErr != nil {
		respondWithError(writer, constants.NOT_FOUND, "User not found")
		return
	}

	// The event is user.upgraded. Upgrade the user
	if err := cfg.Db.UpgradeChirpyRed(request.Context(), userInDb.ID); err != nil {
		respondWithError(writer, constants.SERVER_ERROR, err.Error())
		return
	}

	// If everything is successful, return a no content response
	writer.WriteHeader(constants.NO_CONTENT)
}

// Delete Chirp
func (cfg *ApiConfig) DeleteChirp(writer http.ResponseWriter, request *http.Request) {

	// Authorize User
	userId, authTokenErr := cfg.getUserIdFromAuthToken(request.Header)
	if authTokenErr != nil {
		respondWithError(writer, constants.UNAUTHORIZED, authTokenErr.Error())
		return
	}

	// Get chirp_id from request
	chirpIdFromRequest := request.PathValue("chirp_id")
	// Parse the chirp_id
	chirpUUID, uuidErr := uuid.Parse(chirpIdFromRequest)
	if uuidErr != nil {
		respondWithError(writer, constants.BAD_REQUEST, uuidErr.Error())
		return
	}

	// Get Chirp From Db
	chirpFromDb, getChirpErr := cfg.Db.GetChirp(request.Context(), chirpUUID)
	if getChirpErr != nil {
		respondWithError(writer, constants.NOT_FOUND, "No chirps found.")
		return
	}

	// Return FORBIDDEN error if the user is not the author
	if chirpFromDb.UserID.UUID != userId {
		respondWithError(writer, constants.FORBIDDEN, "Only the chirp's author is allowed to delete.")
		return
	}

	// Delete the chirp
	if err := cfg.Db.DeleteChirp(request.Context(), chirpFromDb.ID); err != nil {
		respondWithError(writer, constants.SERVER_ERROR, err.Error())
		return
	}
	// Respond with no content (successful)
	writer.WriteHeader(constants.NO_CONTENT)
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
		Body string `json:"body"`
	}

	// Get Auth token from header
	authToken, authTokenErr := auth.GetBearerToken(request.Header)
	if authTokenErr != nil {
		respondWithError(writer, constants.SERVER_ERROR, authTokenErr.Error())
		return
	}

	// Validate token and get the user_id
	userId, validateJWTErr := auth.ValidateJWT(authToken, cfg.TokenSecret)
	if validateJWTErr != nil {
		respondWithError(writer, constants.UNAUTHORIZED, validateJWTErr.Error())
		return
	}

	// Parse the request
	decoder := json.NewDecoder(request.Body)
	requestParams := requestParameters{}
	if err := decoder.Decode(&requestParams); err != nil {
		respondWithError(writer, constants.SERVER_ERROR, err.Error())
		return
	}

	// Check if the user exists in db
	_, userErr := cfg.Db.GetUserById(request.Context(), userId)
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

	// Insert the chirp into DB
	createChirpParams := database.CreateChirpParams{
		Body: cleanedBody,
		UserID: uuid.NullUUID{
			UUID:  userId,
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

// Revoke RefreshToken
func (cfg *ApiConfig) RevokeRefreshToken(writer http.ResponseWriter, request *http.Request) {
	// Get refresh token from header
	refreshToken, err := auth.GetBearerToken(request.Header)
	if err != nil {
		respondWithError(writer, constants.SERVER_ERROR, err.Error())
		return
	}

	// Check if refresh token exists
	refreshTokenFromDb, refreshTokenErr := cfg.Db.GetRefreshToken(request.Context(), refreshToken)
	// Refresh token doesn't exist. Return 204 to avoid leaking info
	if refreshTokenErr != nil {
		writer.WriteHeader(constants.NO_CONTENT)
		return
	}
	// Refresh token is already revoked. Return 204 to avoid leaking info
	if refreshTokenFromDb.RevokedAt.Valid {
		writer.WriteHeader(constants.NO_CONTENT)
		return
	}

	// Update the db
	if err := cfg.Db.RevokeToken(request.Context(), refreshTokenFromDb.Token); err != nil {
		respondWithError(writer, constants.SERVER_ERROR, err.Error())
		return
	}

	// Successful. return an empty body.
	writer.WriteHeader(constants.NO_CONTENT)
}

// Refresh Token
func (cfg *ApiConfig) RefreshToken(writer http.ResponseWriter, request *http.Request) {
	// Get refresh token from header
	refreshToken, err := auth.GetBearerToken(request.Header)
	if err != nil {
		respondWithError(writer, constants.SERVER_ERROR, err.Error())
		return
	}

	// Check if refresh token exists
	refreshTokenFromDb, refreshTokenErr := cfg.Db.GetRefreshToken(request.Context(), refreshToken)
	if refreshTokenErr != nil {
		respondWithError(writer, constants.UNAUTHORIZED, "Invalid refresh token")
		return
	}

	// Check if refresh token is already revoked
	if refreshTokenFromDb.RevokedAt.Valid {
		respondWithError(writer, constants.UNAUTHORIZED, "Refresh token is no longer valid.")
		return
	}

	// Check if refresh token is expired
	if time.Now().After(refreshTokenFromDb.ExpiresAt) {
		respondWithError(writer, constants.UNAUTHORIZED, "Refresh token has been expired.")
		return
	}

	// Make new jwt token
	newJWTToken, jwtErr := auth.MakeJWT(refreshTokenFromDb.UserID, cfg.TokenSecret, utils.GetJWTTokenExpireTime())
	if jwtErr != nil {
		respondWithError(writer, constants.SERVER_ERROR, jwtErr.Error())
		return
	}

	// Return the new jwt token
	refreshTokenResponse := RefreshTokenResponse{
		Token: newJWTToken,
	}
	respondWithJSON(writer, constants.SUCCESS, refreshTokenResponse)
}

// Login
func (cfg *ApiConfig) Login(writer http.ResponseWriter, request *http.Request) {
	// Read the request
	// Read input param
	type requestParameters struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}

	// Decode the request
	decoder := json.NewDecoder(request.Body)
	requestParams := requestParameters{}
	if err := decoder.Decode(&requestParams); err != nil {
		respondWithError(writer, constants.SERVER_ERROR, err.Error())
		return
	}

	// Verify the password
	user, err := cfg.Db.GetUserByEmail(request.Context(), requestParams.Email)
	if err != nil {
		respondWithError(writer, constants.NOT_FOUND, "No account found for this email address. Please try again")
		return
	}

	// Check password
	if err := auth.CheckPasswordHash(user.HashedPassword, requestParams.Password); err != nil {
		respondWithError(writer, constants.UNAUTHORIZED, "Incorrect password. Please try again.")
		return
	}

	// Make JWT Token
	authToken, tokenErr := auth.MakeJWT(user.ID, cfg.TokenSecret, utils.GetJWTTokenExpireTime())
	if tokenErr != nil {
		respondWithError(writer, constants.SERVER_ERROR, tokenErr.Error())
		return
	}

	// Make Refresh Token
	refreshToken, refreshTokenErr := auth.MakeRefreshToken()
	if refreshTokenErr != nil {
		respondWithError(writer, constants.SERVER_ERROR, refreshTokenErr.Error())
		return
	}
	// Insert refresh token into DB
	refreshTokenParams := database.CreateRefreshTokenParams{
		Token:     refreshToken,
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(utils.GetRefreshTokenDuration()),
	}
	createdRefreshToken, refreshTokenInsertErr := cfg.Db.CreateRefreshToken(request.Context(), refreshTokenParams)
	if refreshTokenInsertErr != nil {
		respondWithError(writer, constants.SERVER_ERROR, refreshTokenInsertErr.Error())
	}

	// Successful. Return the user
	loginResponse := LoginResponse{
		ID:           user.ID,
		CreatedAt:    user.CreatedAt,
		UpdatedAt:    user.UpdatedAt,
		Email:        user.Email,
		Token:        authToken,
		RefreshToken: createdRefreshToken.Token,
		IsChirpyRed:  user.IsChirpyRed.Bool,
	}
	respondWithJSON(writer, constants.SUCCESS, loginResponse)
}

// Create user
func (cfg *ApiConfig) CreateUser(writer http.ResponseWriter, request *http.Request) {
	// Read the request
	// Read input param
	type requestParameters struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}

	// Get the email from request
	decoder := json.NewDecoder(request.Body)
	requestParams := requestParameters{}
	if err := decoder.Decode(&requestParams); err != nil {
		respondWithError(writer, constants.SERVER_ERROR, err.Error())
		return
	}

	// Get the password from request and hash it
	hashedPass, hashErr := auth.HashPassword(requestParams.Password)
	if hashErr != nil {
		respondWithError(writer, constants.BAD_REQUEST, hashErr.Error())
		return
	}

	// Insert user into db
	createUserParams := database.CreateUserParams{
		Email:          requestParams.Email,
		HashedPassword: hashedPass,
	}
	insertedUser, userInsertErr := cfg.Db.CreateUser(request.Context(), createUserParams)
	if userInsertErr != nil {
		respondWithError(writer, constants.SERVER_ERROR, userInsertErr.Error())
		return
	}
	// Set up user response. User response will not include password
	userResponse := UserResponse{
		ID:          insertedUser.ID,
		CreatedAt:   insertedUser.CreatedAt,
		UpdatedAt:   insertedUser.UpdatedAt,
		Email:       insertedUser.Email,
		IsChirpyRed: insertedUser.IsChirpyRed.Bool,
	}

	// User successfully created
	respondWithJSON(writer, constants.CREATED, userResponse)
}

// Update user
func (cfg *ApiConfig) UpdateUser(writer http.ResponseWriter, request *http.Request) {
	// Validate token and get the user_id
	userId, tokenErr := cfg.getUserIdFromAuthToken(request.Header)
	if tokenErr != nil {
		respondWithError(writer, constants.UNAUTHORIZED, tokenErr.Error())
		return
	}

	// Get the email and password from request
	emailAndPasswordReq, reqErr := getEmailAndPasswordFromRequest(request)
	if reqErr != nil {
		respondWithError(writer, constants.SERVER_ERROR, reqErr.Error())
		return
	}

	// Hash the password given
	hashedPass, hashErr := auth.HashPassword(emailAndPasswordReq.Password)
	if hashErr != nil {
		respondWithError(writer, constants.SERVER_ERROR, hashErr.Error())
		return
	}

	// Update the email and password in Db
	updateUserParams := database.UpdateUserParams{
		ID:             userId,
		Email:          emailAndPasswordReq.Email,
		HashedPassword: hashedPass,
	}
	updatedUser, updateErr := cfg.Db.UpdateUser(request.Context(), updateUserParams)
	if updateErr != nil {
		respondWithError(writer, constants.SERVER_ERROR, updateErr.Error())
		return
	}

	// Create the response and return
	response := UserResponse{
		ID:          updatedUser.ID,
		CreatedAt:   updatedUser.CreatedAt,
		UpdatedAt:   updatedUser.UpdatedAt,
		Email:       updatedUser.Email,
		IsChirpyRed: updatedUser.IsChirpyRed.Bool,
	}

	respondWithJSON(writer, constants.SUCCESS, response)
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
