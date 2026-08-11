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
	sqlBytes, err := os.ReadFile("migrations/001_create_samples.sql")
	if err != nil {
		return fmt.Errorf("failed to read migration: %w", err)
	}

	if _, err := pool.Exec(context.Background(), string(sqlBytes)); err != nil {
		return fmt.Errorf("failed to execute migration: %w", err)
	}

	return nil
}