package main

import (
	"fmt"
	"log"
	"net/http"
	"crypto/sha256"
	"io"
	"encoding/hex"
	"context"
	"os"
	"encoding/json"

	"github.com/joho/godotenv"
	"github.com/jackc/pgx/v5/pgxpool"

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

	//routes
	mux.HandleFunc("/", home)

	mux.HandleFunc("/api/samples", func(w http.ResponseWriter, r *http.Request) {
		CreateSample(w, r, db, storageService)
	})

	fmt.Println("Server running on :8080")

	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatal(err)
	}
}

func home(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "Hello world")
}

func CreateSample(w http.ResponseWriter, r *http.Request, db *pgxpool.Pool, storageService *storage.StorageService,){
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	file, header, err := r.FormFile("file")
	
	if err != nil {
		http.Error(w, "File is required", http.StatusBadRequest)
		return
	}
	defer file.Close()

	//validation
	if header.Size == 0 || header.Size > 100*1024*1024{
		http.Error(w, "Size not valid", http.StatusBadRequest)
		return
	}

	//calculate sha-256
	hash := sha256.New()
	
	_, err = io.Copy(hash, file)
	if err != nil {
		http.Error(w, "Failed to hash file", http.StatusInternalServerError)
		return
	}

	sum := hash.Sum(nil)
	sha256Hash := hex.EncodeToString(sum)

	_, err = file.Seek(0, io.SeekStart)
	if err != nil {
		http.Error(w, "Failed to reset file", http.StatusInternalServerError)
		return
	}

	var exists bool
	
	err = db.QueryRow(
		context.Background(),
		"SELECT EXISTS (SELECT 1 FROM samples WHERE sha256 = $1)",
		sha256Hash,
	).Scan(&exists)

	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	if exists {
		http.Error(w, "Sample already exists", http.StatusConflict)
		return
	} 

	err = os.MkdirAll("uploads", 0755)
	if err != nil {
		http.Error(w, "Failed to create uploads directory", http.StatusInternalServerError)
		return
	}

	storagePath, err := storageService.Save(file, sha256Hash)
	if err != nil {
		http.Error(w, "Failed to save file", http.StatusInternalServerError)
		return
	}

	_, err = db.Exec(
		context.Background(),
		`INSERT INTO samples (
			original_filename,
			sha256,
			file_size,
			storage_path
		)
		VALUES ($1, $2, $3, $4)`,
		header.Filename,
		sha256Hash,
		header.Size,
		storagePath,
	)

	if err != nil {
		http.Error(w, "Failed to save sample metadata", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":      "Sample uploaded successfully",
		"sha256":       sha256Hash,
		"storage_path": storagePath,
	})
}