// ProxyServer.go
package main

import (
	"Encryptionlogic"
	"database/sql"
	"fmt"
	"log"
	"net/http"

	_ "github.com/go-sql-driver/mysql"

	"github.com/gorilla/mux"
)

func main() {

	fmt.Println("Proxy server starting on 8080 port ...")

	db, err := sql.Open("mysql", "root:houssem@tcp(127.0.0.1:3306)/proxy")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	r := mux.NewRouter()
	r.HandleFunc("/saveRKey", Encryptionlogic.RegenKeyAdd(db)).Methods("POST")
	r.HandleFunc("/RenEncCipher", Encryptionlogic.RenEncryptionCipher(db)).Methods("post")
	r.HandleFunc("/RemoveKey", Encryptionlogic.RegenKeyDelete(db)).Methods("post")
	log.Fatal(http.ListenAndServe(":8082", r))
}
