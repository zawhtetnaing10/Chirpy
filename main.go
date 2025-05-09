package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/zawhtetnaing10/Chirpy/constants"
	"github.com/zawhtetnaing10/Chirpy/internal/database"

	"database/sql"
	"os"

	"log"

	_ "github.com/lib/pq"
)

// In memory data
type apiConfig struct {
	fileServerHits atomic.Int32
	db             *database.Queries
}

// Middleware to increase request count
func (cfg *apiConfig) middlewareMetricsInc(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		cfg.fileServerHits.Add(1)
		handler.ServeHTTP(writer, request)
	})
}

// Metrics Handler
func (cfg *apiConfig) metricsHandler(writer http.ResponseWriter, request *http.Request) {
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
	`, cfg.fileServerHits.Load())
	writer.Write([]byte(responseString))
}

// Reset file server hits
func (cfg *apiConfig) resetHandler(writer http.ResponseWriter, request *http.Request) {

	// Convert file server hits atomic.Int32 back to zero
	cfg.fileServerHits.Store(0)

	// Set status code
	writer.WriteHeader(http.StatusOK)
}

// Validate chirp handler
func validateChirpHandler(writer http.ResponseWriter, request *http.Request) {
	// Read input param
	type parameters struct {
		Body string `json:"body"`
	}

	decoder := json.NewDecoder(request.Body)
	params := parameters{}

	// Prepare response body
	type returnVals struct {
		CleanedBody string `json:"cleaned_body"`
	}

	// Check for parsing errors
	if err := decoder.Decode(&params); err != nil {
		respondWithError(writer, constants.SERVER_ERROR, "Something went wrong")
		return
	}

	// Take care of a case where length > 140
	if len(params.Body) > 140 {
		respondWithError(writer, constants.BAD_REQUEST, "Chirp is too long")
		return
	}

	// Censor the profane words
	profaneWords := []string{"kerfuffle", "sharbert", "fornax"}
	censoredWord := "****"
	words := strings.Split(params.Body, " ")
	for i := 0; i < len(words); i++ {
		for _, profaneWord := range profaneWords {
			if strings.ToLower(words[i]) == profaneWord {
				words[i] = censoredWord
			}
		}
	}
	cleanedOutput := strings.Join(words, " ")

	// The request is valid.
	validRes := returnVals{
		CleanedBody: cleanedOutput,
	}
	respondWithJSON(writer, constants.SUCCESS, validRes)
}

// / Helper function to respond with json
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

// / Helper function to respond with error
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

func main() {

	// Get dburl from env
	dbURL := os.Getenv("DB_URL")

	// Open DB
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	// New http server mux
	mux := http.NewServeMux()

	// Config
	apiCfg := apiConfig{
		db: database.New(db),
	}
	apiCfg.fileServerHits.Store(0)

	// Set up file server with mux
	fileServerHandler := http.StripPrefix("/app/", http.FileServer(http.Dir(".")))
	mux.Handle("/app/", apiCfg.middlewareMetricsInc(fileServerHandler))

	// Handle healthz
	mux.HandleFunc("GET /api/healthz", readinessHandler)
	mux.HandleFunc("GET /admin/metrics", apiCfg.metricsHandler)
	mux.HandleFunc("POST /admin/reset", apiCfg.resetHandler)
	mux.HandleFunc("POST /api/validate_chirp", validateChirpHandler)

	// New http server
	server := http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	// Start the server
	server.ListenAndServe()
}

// Readiness handler
func readinessHandler(writer http.ResponseWriter, request *http.Request) {
	// Set content type in header
	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	// Set status code
	writer.WriteHeader(http.StatusOK)
	// Set response
	writer.Write([]byte("OK"))
}
