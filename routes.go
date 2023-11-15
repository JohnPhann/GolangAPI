package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"net/http"

	"github.com/labstack/echo/v4"
)

// User represents a user model
type Users struct {
	ID           int    `json:"id"`
	Email        string `json:"email"`
	Password     string `json:"password"`
	RefreshToken string `json:"refreshToken"`
	ApiKey       string `json:"apiKey"`
}

type Todo struct {
	ID    int    `json:"id"`
	Title string `json:"title"`
}

type ResponseData struct {
	Message string `json:"message"`
	ApiKey  string `json:"apikey"`
}

// POST : v1/admin/GetApiKey
func GetApiKey(c echo.Context) error {
	// Bind the request body to a struct
	var request struct {
		Email string `json:"email" form:"email"`
	}

	if err := c.Bind(&request); err != nil {
		return c.String(http.StatusBadRequest, "Invalid request")
	}
	//init db
	db, error := initDB()
	if error != nil {
		return nil
	}
	// // Validate the request
	// if err := c.Validate(request); err != nil {
	// 	return c.String(http.StatusBadRequest, "Invalid email address")
	// }

	// Check if the email exists in the database
	exists, err := emailExists(request.Email, db)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Error checking email")
	}

	if exists {
		return c.String(http.StatusOK, "Email exists in the database")
	}
	apiKey, err := generateAPIKey()
	if err != nil {
		return nil
	}
	responseData := ResponseData{
		Message: "Email does not exist in the database",
		ApiKey:  apiKey,
	}
	err = insertEmail(request.Email, apiKey, db)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Error saving email")
	}
	return c.JSON(http.StatusOK, responseData)
}

func emailExists(email string, db *sql.DB) (bool, error) {

	err := db.QueryRow("SELECT email FROM users WHERE email = ?", email).Scan(&email)
	if err == sql.ErrNoRows {
		// Email not found in the database
		return false, nil
	} else if err != nil {
		// Some other error occurred
		return false, err
	}

	// Email found in the database
	return true, nil
}

func generateAPIKey() (string, error) {
	// Generate a random byte slice (you can adjust the length as needed)
	keyBytes := make([]byte, 32)
	_, err := rand.Read(keyBytes)
	if err != nil {
		return "", err
	}

	// Convert the byte slice to a hexadecimal string
	apiKey := hex.EncodeToString(keyBytes)

	return apiKey, nil
}

func insertEmail(email string, apiKey string, db *sql.DB) error {
	_, err := db.Exec("INSERT INTO users (email ,apiKey) VALUES (?,?)", email, apiKey)
	return err
}
