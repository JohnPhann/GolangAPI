package main

import (
	"database/sql"
	"log"
	"net/http"
	"os"
	"strings"

	_ "github.com/go-sql-driver/mysql"
	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
)

// CustomClaims represents the claims in the JWT token
type CustomClaims struct {
	UserID int64 `json:"user_id"`
	Exp    int64 `json:"exp"`
}

// // Valid implements jwt.Claims.
// func (*CustomClaims) Valid() error {
// 	panic("unimplemented")
// }

func initDB() (*sql.DB, error) {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	dbName := os.Getenv("DB_Name")

	dataSourceName := dbUser + ":" + dbPassword + "@tcp(" + dbHost + ":" + dbPort + ")/" + dbName
	db, err := sql.Open("mysql", dataSourceName)
	if err != nil {
		return nil, err
	}
	// Create the "users" and "products" tables
	if err := CreateTables(db); err != nil {
		return nil, err
	}

	return db, nil
}

func main() {
	// initDB
	initDB()
	// Create a new Echo instance
	e := echo.New()
	// Secret key for signing and validating the JWT token

	// Middleware for JWT authentication
	// e.Use(middleware.JWTWithConfig(middleware.JWTConfig{
	// 	SigningKey: []byte(os.Getenv("SECRET_KEY")),
	// 	// Customize TokenLookup to extract token from the Authorization header
	// 	TokenLookup: "header:Authorization",
	// }))

	// Define a route
	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "Hello, Echo!")
	}, ExtractTokenFromHeader)
	e.POST("/getApikey", GetApiKey)
	e.POST("/v1/admins", CreateAdmin)
	e.POST("/v1/admins/sign-in", SignInAdmin)
	e.POST("/v1/admins/acess-token", refreshToken)
	e.GET("/v1/admins/todos", GetTodos, ExtractTokenFromHeader)
	// Start the server
	e.Start(":8080")
}

// Middleware to extract token from the Authorization header
func ExtractTokenFromHeader(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		authHeader := c.Request().Header.Get("Authorization")
		if authHeader == "" {
			return echo.NewHTTPError(http.StatusUnauthorized, "Authorization header is missing")
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			return echo.NewHTTPError(http.StatusUnauthorized, "Invalid Authorization header format")
		}
		secretkey := os.Getenv("SECRET_KEY")
		// Check if the refreshToken exists in the database
		exits := DecodeJWT(parts[1], secretkey)
		if !exits {
			return echo.NewHTTPError(http.StatusUnauthorized, "Token verification failed")
		}
		c.Set("token", parts[1])
		return next(c)
	}
}
