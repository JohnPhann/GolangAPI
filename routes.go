package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
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

type Claims struct {
	UserID int `json:"user_id"`
	jwt.StandardClaims
}

type Todo struct {
	ID    int    `json:"id"`
	Title string `json:"title"`
	Name  string `json:"name"`
}

type ResponseData struct {
	Message string `json:"message"`
	ApiKey  string `json:"apikey"`
}

type ResponseDataLogin struct {
	Message      string `json:"message"`
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

type ResponseDataRefreshToken struct {
	Message         string `json:"message"`
	NewAccessToken  string `json:"accessToken"`
	NewRefreshToken string `json:"refreshToken"`
}

// POST : /GetApiKey
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

// POST : v1/admin
func CreateAdmin(c echo.Context) error {

	var request struct {
		Email    string `json:"email" form:"email"`
		Password string `json:"password" form:"password"`
		ApiKey   string `json:"apikey" form:"apikey"`
	}

	if err := c.Bind(&request); err != nil {
		return c.String(http.StatusBadRequest, "Invalid request")
	}
	//init db
	db, error := initDB()
	if error != nil {
		return nil
	}
	// Check if the apiKey exists in the database
	exists, err := apiKeyExists(request.ApiKey, request.Email, db)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Error checking apiKey")
	}

	if !exists {
		return c.String(http.StatusOK, "ApiKey not exists in the database")
	}
	err = insertPassword(request.Email, request.Password, db)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Error saving Password")
	}
	return c.JSON(http.StatusOK, "You created Account Admin sucess !!")
}

// POST: Admin/Sign-in
func SignInAdmin(c echo.Context) error {
	secret_key := os.Getenv("SECRET_KEY")
	var request struct {
		Email    string `json:"email" form:"email"`
		Password string `json:"password" form:"password"`
	}
	if err := c.Bind(&request); err != nil {
		return c.String(http.StatusBadRequest, "Invalid request")
	}
	//init db
	db, error := initDB()
	if error != nil {
		return nil
	}
	// Check if the apiKey exists in the database
	exists, err := AuthenticationUser(request.Email, request.Password, db)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Error checking User")
	}
	if !exists {
		return c.String(http.StatusOK, "User not exists ")
	}
	user_id, err := getUserIDByEmail(db, request.Email)
	if err != nil {
		return err
	}
	// Generate access token
	accessToken, err := generateToken(user_id, time.Now().Add(time.Minute*5), secret_key)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Error generating access token")
	}
	// Generate refresh token
	refreshToken, err := generateToken(user_id, time.Now().Add(time.Hour*24*7), secret_key)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Error generating refresh token")
	}
	responseDataLogin := ResponseDataLogin{
		Message:      "You Login Account Admin sucess !!",
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}
	err = insertRefreshToken(request.Email, refreshToken, db)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Error saving refreshToken")
	}
	return c.JSON(http.StatusOK, responseDataLogin)
}

// POST: Admin/refreshToken
func refreshToken(c echo.Context) error {
	secret_key := os.Getenv("SECRET_KEY")

	var request struct {
		Email        string `json:"email" form:"email"`
		RefreshToken string `json:"refreshToken" form:"refreshToken"`
	}
	if err := c.Bind(&request); err != nil {
		return c.String(http.StatusBadRequest, "Invalid request")
	}
	//init db
	db, error := initDB()
	if error != nil {
		return nil
	}
	// get User_id with Email request
	user_id, err := getUserIDByEmail(db, request.Email)
	if err != nil {
		return err
	}
	// Check if the refreshToken exists in the database
	exists, err := refreshTokenExists(request.RefreshToken, request.Email, db)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Error checking RefreshToken")
	}
	if !exists {
		return c.String(http.StatusOK, "RefreshToken not exists ")
	}
	// Generate access token
	accessToken, err := generateToken(user_id, time.Now().Add(time.Minute*5), secret_key)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Error generating access token")
	}
	// Generate refresh token
	refreshToken, err := generateToken(user_id, time.Now().Add(time.Hour*24*7), secret_key)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Error generating refresh token")
	}
	responseDataRefreshToken := ResponseDataRefreshToken{
		Message:         "Refresh Token sucess !!",
		NewAccessToken:  accessToken,
		NewRefreshToken: refreshToken,
	}
	err = insertRefreshToken(request.Email, refreshToken, db)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Error saving refreshToken")
	}
	return c.JSON(http.StatusOK, responseDataRefreshToken)
}

// POST : /v1/admins/todos
func GetTodos(c echo.Context) error {
	//init db
	db, error := initDB()
	if error != nil {
		return nil
	}
	todos, err := GetAllTodos(db)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, todos)
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

func AuthenticationUser(email string, password string, db *sql.DB) (bool, error) {

	err := db.QueryRow("SELECT email , password FROM users WHERE email = ? and password = ?", email, password).Scan(&email, &password)
	if err == sql.ErrNoRows {
		// User not found in the database
		return false, nil
	} else if err != nil {
		// Some other error occurred
		return false, err
	}

	// User found in the database
	return true, nil
}

func GetAllTodos(db *sql.DB) ([]Todo, error) {

	rows, err := db.Query("SELECT id, title, name FROM todo")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var todos []Todo
	for rows.Next() {
		var todo Todo
		if err := rows.Scan(&todo.ID, &todo.Title, &todo.Name); err != nil {
			return nil, err
		}
		todos = append(todos, todo)
	}

	return todos, nil
}

func apiKeyExists(apiKey string, email string, db *sql.DB) (bool, error) {

	err := db.QueryRow("SELECT apiKey FROM users WHERE apiKey = ? AND email= ?", apiKey, email).Scan(&apiKey)
	if err == sql.ErrNoRows {
		// api not found in the database
		return false, nil
	} else if err != nil {
		// Some other error occurred
		return false, err
	}

	// api found in the database
	return true, nil
}

func DecodeJWT(tokenString string, secretKey string) bool {
	// Split the token into parts
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		fmt.Print("Token is Valid not format")
		return false
	}

	// Decode and parse the payload (second part)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		fmt.Print("payload error")
		return false
	}

	// Unmarshal the payload into custom claims
	var claims CustomClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		fmt.Print("decode error")
		return false
	}
	result, err := userIdExists(int(claims.UserID))
	if err != nil {
		return false
	}
	return result
}

func userIdExists(id int) (bool, error) {
	db, error := initDB()
	if error != nil {
		return false, nil
	}
	err := db.QueryRow("SELECT id FROM users WHERE id = ? ", id).Scan(&id)
	if err == sql.ErrNoRows {
		// api not found in the database
		return false, nil
	} else if err != nil {
		// Some other error occurred
		return false, err
	}

	// api found in the database
	return true, nil
}

func refreshTokenExists(refreshToken string, email string, db *sql.DB) (bool, error) {

	err := db.QueryRow("SELECT refreshToken FROM users WHERE refreshToken = ? AND email= ?", refreshToken, email).Scan(&refreshToken)
	if err == sql.ErrNoRows {
		// refreshToken not found in the database
		return false, nil
	} else if err != nil {
		// Some other error occurred
		return false, err
	}

	// refreshToken found in the database
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

func insertPassword(email string, password string, db *sql.DB) error {
	_, err := db.Exec("UPDATE users SET password = ? WHERE email = ?", password, email)
	return err
}

func insertRefreshToken(email string, refreshToken string, db *sql.DB) error {
	_, err := db.Exec("UPDATE users SET refreshToken = ? WHERE email = ?", refreshToken, email)
	return err
}

func getUserIDByEmail(db *sql.DB, email string) (int, error) {
	var userID int
	err := db.QueryRow("SELECT id FROM users WHERE email = ?", email).Scan(&userID)
	if err != nil {
		return 0, err
	}
	return userID, nil
}

func generateToken(userID int, expirationTime time.Time, secretKey string) (string, error) {
	claims := &Claims{
		UserID: userID,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secretKey))
}
