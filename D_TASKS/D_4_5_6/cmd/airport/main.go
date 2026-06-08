package main

import (
	"airport/internal/application"
	"airport/internal/config"
	"airport/internal/infrastructure/in"
	"airport/internal/infrastructure/out"

	"context"
	"errors"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := godotenv.Load(); err != nil {
		log.Println("INFO: .env file not found, using system environment variables or defaults")
	}

	cfg := config.Load()

	initCtx, initCancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer initCancel()

    log.Printf("INFO: connecting to database at %s...", cfg.DatabaseDSN)
    pool, err := pgxpool.New(initCtx, cfg.DatabaseDSN)
    if err != nil {
        log.Fatalf("FATAL: unable to create connection pool: %v", err)
    }
    defer pool.Close()

    if err := pool.Ping(initCtx); err != nil {
        log.Fatalf("FATAL: database ping failed: %v", err)
    }
    log.Println("INFO: database connection successfully established")

	repo := out.NewPostgresRepository(pool)
	service := application.NewAirportService(repo)
	handler := in.NewAirportHandler(service)
	server := in.NewServer(cfg.ServerAddress, handler)

	serverErrors := make(chan error, 1)

	go func() {
		log.Printf("INFO: server is starting on %s", cfg.ServerAddress)
		if err := server.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrors <- err
		}
	}()

	select {
	case err := <-serverErrors:
		log.Fatalf("FATAL: server failed to start: %v", err)
	case <-ctx.Done():
		log.Printf("INFO: shutdown signal received (%v). stopping gracefully...", ctx.Err())

		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Printf("ERROR: forced server shutdown: %v", err)
		}
	}

	log.Println("INFO: server stopped successfully. goodbye!")
}
