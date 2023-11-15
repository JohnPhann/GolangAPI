package main

import (
	"database/sql"

	_ "github.com/go-sql-driver/mysql"
)

func CreateTables(db *sql.DB) error {
	query1 := `
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(50),
		password VARCHAR(50),
		refreshToken VARCHAR(255),
		apiKey	VARCHAR(255)
    )`

	query2 := `
    CREATE TABLE IF NOT EXISTS todo (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(50),
        title VARCHAR(50)
    )`

	_, err := db.Exec(query1)
	if err != nil {
		return err
	}

	_, err = db.Exec(query2)
	return err
}
