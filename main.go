package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"
)

// In memory data
type apiConfig struct {
	fileServerHits atomic.Int32
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
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
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
// TODO: - We have things to fix here.
func validateChirpHandler(writer http.ResponseWriter, request *http.Request) {
	// Read input param
	type parameters struct {
		Body string `json:"body"`
	}

	decoder := json.NewDecoder(request.Body)
	params := parameters{}

	// Prepare response body
	type returnVals struct {
		Valid bool `json:"valid"`
	}
	// Prepare error body
	type errorVals struct {
		Error string `json:"error"`
	}

	// Check for parsing errors
	if err := decoder.Decode(&params); err != nil {
		inputReadErr := errorVals{
			Error: "Something went wrong",
		}
		inputReadErrData, err := json.Marshal(inputReadErr)
		if err != nil {
			writer.WriteHeader(500)
			return
		}
		writer.WriteHeader(500)
		writer.Write(inputReadErrData)
		return
	}

	// Take care of a case where length > 140
	if len(params.Body) > 140 {
		tooLongError := errorVals{
			Error: "Chirp is too long",
		}
		errData, err := json.Marshal(tooLongError)
		if err != nil {
			writer.WriteHeader(500)
			return
		}
		writer.WriteHeader(400)
		writer.Write(errData)
		return
	}

	// The request is valid.
	validRes := returnVals{
		Valid: true,
	}
	successData, err := json.Marshal(validRes)
	if err != nil {
		writer.WriteHeader(500)
		return
	}
	writer.WriteHeader(200)
	writer.Write(successData)
}

func main() {
	// New http server mux
	mux := http.NewServeMux()

	// Config
	apiCfg := apiConfig{}
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
