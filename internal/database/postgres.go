package database

import (
	"context"
	"fmt"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
)

func Connect() (*pgxpool.Pool, error) {
	databaseURL := os.Getenv("DATABASE_URL")

	if databaseURL == "" {
		return nil, fmt.Errorf("DATABASE_URL is not set")
	}

	pool, err := pgxpool.New(context.Background(), databaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create database pool: %w", err)
	}

	if err := pool.Ping(context.Background()); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return pool, nil
}

func Migrate(pool *pgxpool.Pool) error {
	migrations := []string{
		"migrations/001_create_samples.sql",
		"migrations/002_create_jobs.sql",
		"migrations/003_create_results.sql",
		"migrations/004_add_job_error.sql",
	}

	for _, path := range migrations {
		sqlBytes, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read migration %s: %w", path, err)
		}

		if _, err := pool.Exec(context.Background(), string(sqlBytes)); err != nil {
			return fmt.Errorf("failed to execute migration %s: %w", path, err)
		}
	}

	return nil
}