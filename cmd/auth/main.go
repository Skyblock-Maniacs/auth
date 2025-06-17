package main

import (
	"os"

	"github.com/Skyblock-Maniacs/auth/auth"
	"github.com/Skyblock-Maniacs/auth/internal/db"
	"github.com/Skyblock-Maniacs/auth/internal/logger"
	"github.com/joho/godotenv"
)

func main() {
	if err := godotenv.Load(); err != nil {
		logger.Error.Fatal("Error loading .env file: ", err)
	}

	database, err := db.Connect(os.Getenv("MONGO_URI"))
	if err != nil {
		logger.Error.Fatal("Failed to connect to database: ", err)
	} else {
		logger.Info.Println("Connected to MongoDB successfully")
	}

	defer database.Disconnect(nil)

	auth.Run(database)
}
