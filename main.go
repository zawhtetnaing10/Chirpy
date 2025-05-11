package main

import (
	"net/http"

	"github.com/joho/godotenv"
	"github.com/zawhtetnaing10/Chirpy/handlers"
	"github.com/zawhtetnaing10/Chirpy/internal/database"

	"os"

	"database/sql"
	"log"
)

func main() {

	// Load environment file
	godotenv.Load()

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
	apiCfg := handlers.ApiConfig{
		Db:          database.New(db),
		Platform:    os.Getenv("PLATFORM"),
		TokenSecret: os.Getenv("TOKEN_SECRET"),
		PolkaKey:    os.Getenv("POLKA_KEY"),
	}
	apiCfg.FileServerHits.Store(0)

	// Set up file server with mux
	fileServerHandler := http.StripPrefix("/app/", http.FileServer(http.Dir(".")))
	mux.Handle("/app/", apiCfg.MiddlewareMetricsInc(fileServerHandler))

	// Handle healthz
	mux.HandleFunc("GET /api/healthz", handlers.ReadinessHandler)
	mux.HandleFunc("GET /admin/metrics", apiCfg.MetricsHandler)
	mux.HandleFunc("POST /admin/reset", apiCfg.ResetHandler)
	mux.HandleFunc("POST /api/users", apiCfg.CreateUser)
	mux.HandleFunc("PUT /api/users", apiCfg.UpdateUser)
	mux.HandleFunc("POST /api/login", apiCfg.Login)
	mux.HandleFunc("POST /api/chirps", apiCfg.CreateChirp)
	mux.HandleFunc("GET /api/chirps", apiCfg.GetAllChirps)
	mux.HandleFunc("GET /api/chirps/{chirp_id}", apiCfg.GetChirp)
	mux.HandleFunc("DELETE /api/chirps/{chirp_id}", apiCfg.DeleteChirp)
	mux.HandleFunc("POST /api/refresh", apiCfg.RefreshToken)
	mux.HandleFunc("POST /api/revoke", apiCfg.RevokeRefreshToken)
	mux.HandleFunc("POST /api/polka/webhooks", apiCfg.UpgradeChirpyRed)

	// New http server
	server := http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	// Start the server
	server.ListenAndServe()
}
