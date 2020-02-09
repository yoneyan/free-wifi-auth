package main

import (
	"database/sql"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"log"
)

const db_name = "./main.sql"

func connectdb() *sql.DB {
	db, err := sql.Open("sqlite3", db_name)
	if err != nil {
		log.Fatalln(err)
		fmt.Println("SQL open error")
		panic(err)
	}

	//defer db.Close()

	return db
}

func createdb(database string) bool {
	db := *connectdb()

	_, err := db.Exec(database)
	if err != nil {
		log.Fatalln(err)
		return false
	}
	return true
}

func initdb() bool {
	createdb(`CREATE TABLE IF NOT EXISTS "user" ("id" INTEGER PRIMARY KEY, "name" VARCHAR(255), "pass" VARCHAR(255))`)

	return true
}

//User

func addDBUser(user, pass string) bool {
	db := connectdb()
	addDb, err := db.Prepare(`INSERT INTO "user" ("name","pass") VALUES (?,?)`)
	if err != nil {
		panic(err)
		return false
	}

	if _, err := addDb.Exec(user, hashgenerate(pass)); err != nil {
		panic(err)
		return false
	}

	return true
}

func deleteDBUser(name string) bool {
	db := connectdb()
	deleteDb := "DELETE FROM user WHERE name = ?"
	_, err := db.Exec(deleteDb, name)
	if err != nil {
		log.Fatalln(err)
		return false
	}
	return true
}

func TestPassDBUser(name, pass string) bool {
	db := connectdb()
	var hash string
	if err := db.QueryRow("SELECT pass FROM user WHERE name = ?", name).Scan(&hash); err != nil {
		return false
	}

	return verifyhashdata(pass, hash)
}
