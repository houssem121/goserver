package main

import (
	"Encryptionlogic"
	"database/sql"
	"fmt"
	"log"
	"net/http"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
)

// make a symKey

/*
func removeaccess(w http.ResponseWriter, r *http.Request) {

}
*/

// Main function
func main() {
	fmt.Println("Server is running on port 8083 ...")
	db, err := sql.Open("mysql", "root:houssem@tcp(127.0.0.1:3306)/patiens")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Init router
	r := mux.NewRouter()
	r.HandleFunc("/keygen", Encryptionlogic.KeyGen(db)).Methods("post")
	r.HandleFunc("/uploadfile", Encryptionlogic.Encryptfile(db)).Methods("post")
	r.HandleFunc("/giveaccess", Encryptionlogic.Giveaccess(db)).Methods("post")
	r.HandleFunc("/downloadfile", Encryptionlogic.Decryptfile(db)).Methods("POST")
	//r.HandleFunc("/revoce", encryptionlogic.SendRegenKeyToProxy).Methods("post")
	r.HandleFunc("/removeaccess", Encryptionlogic.Removeaccess(db)).Methods("delete")
	// Start server
	c := cors.New(cors.Options{
		AllowedOrigins: []string{"http://localhost:3000"}, // Allow requests from this origin
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"*"},
		Debug:          true,
	})

	// Use CORS middleware with your router
	handler := c.Handler(r)

	// Start server with CORS middleware
	log.Fatal(http.ListenAndServe(":8083", handler))
}
