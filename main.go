package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/joho/godotenv"

	"github.com/aasimkhan02/ThreatBox/internal/database"
	"github.com/aasimkhan02/ThreatBox/internal/storage"
)

func main() {
	mux := http.NewServeMux()

	if err := godotenv.Load(); err != nil {
		log.Fatal("Error loading .env")
	}

	db, err := database.Connect()
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	fmt.Println("Connected to PostgreSQL!")

	if err := database.Migrate(db); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Database migrations completed!")

	storageService := storage.NewFilesystem("uploads")

	go StartWorker(db)

	//routes
	mux.HandleFunc("/", home)

	mux.HandleFunc("/api/samples", func(w http.ResponseWriter, r *http.Request) {
		CreateSample(w, r, db, storageService)
	})

	mux.HandleFunc("/api/jobs", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			GetMultipleJobsHandler(w, r, db)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/api/jobs/{id}", func(w http.ResponseWriter, r *http.Request) {
		jobID := r.PathValue("id")

		switch r.Method {
		case http.MethodGet:
			GetJobHandler(w, r, db, jobID)

		case http.MethodPatch:
			UpdateStatusHandler(w, r, db, jobID)

		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	fmt.Println("Server running on :8080")

	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatal(err)
	}
}

func home(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "Hello world")
}
