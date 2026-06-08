package config

import (
	"fmt"
	"os"
	"strings"
)

type Config struct {
	ServerAddress string
	DatabaseDSN   string
}

func Load() *Config {
	serverHost := getEnv("SERVER_HOST", "localhost")
	serverPort := getEnv("SERVER_PORT", "8000")
	serverAddr := fmt.Sprintf("%s:%s", serverHost, serverPort)

	dbUser := getEnv("DB_USER", "postgres")
	dbPass := getEnv("DB_PASSWORD", "postgres")
	dbHost := getEnv("DB_HOST", "localhost")
	dbPort := getEnv("DB_PORT", "5432")
	dbName := getEnv("DB_NAME", "demo")

	dsn := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
		dbUser, dbPass, dbHost, dbPort, dbName,
	)

	return &Config{
		ServerAddress: serverAddr,
		DatabaseDSN:   dsn,
	}
}

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			return trimmed
		}
	}
	return defaultValue
}