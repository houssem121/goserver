package Encryptionlogic

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"goRecrypt/curve"
	"goRecrypt/recrypt"
	"io/ioutil"
	"keygenD"
	"math/big"
	"models"

	"net/http"
)

func KeyGen(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var requestBody models.RequestBody
		if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
			http.Error(w, "Failed to parse request body", http.StatusBadRequest)
			return
		}
		blockchainAddress := requestBody.BlockchainAddress
		fmt.Println("this is the blockchain address", blockchainAddress)
		// Check if patient already has a key
		var publicKey, privateKey string
		err := db.QueryRow("SELECT pub_key, priv_key FROM patiens WHERE blockchain_address = ?", blockchainAddress).Scan(&publicKey, &privateKey)
		if err == sql.ErrNoRows {

			aPriKey, aPubKey, _ := curve.GenerateKeys()
			publicKey = fmt.Sprintf("%v", aPubKey)  // Convert bytes to string
			privateKey = fmt.Sprintf("%v", aPriKey) // Convert aPriKey to string
			encryptedPubKey, _ := keygenD.GetAESEncrypted(publicKey)
			encryptedPriKey, _ := keygenD.GetAESEncrypted(privateKey)
			//	publicKey = fmt.Sprintf("%v", encryptedPubKey) // Convert bytes to string
			//	privateKey = fmt.Sprintf("%v", encryptedPriKey)
			fmt.Println("this is the public key", publicKey)
			fmt.Println("this is the private key", privateKey)
			fmt.Println("this is the encrypted public key", encryptedPubKey)
			fmt.Println("this is the encrypted private key", encryptedPriKey)
			_, err := db.Exec("INSERT INTO patiens (blockchain_address, pub_key, priv_key) VALUES (?, ?, ?)", blockchainAddress, encryptedPubKey, encryptedPriKey)
			if err != nil {
				http.Error(w, "Failed to store key pair in database", http.StatusInternalServerError)
				return
			}

			keys := struct {
				PublicKey string `json:"public_key"`
			}{
				PublicKey: publicKey,
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(keys)

		} else if err != nil {
			http.Error(w, "Failed to query database", http.StatusInternalServerError)
			return
		}
	}
}

func Encryptfile(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var requestBody models.RequestfileEnc
		err := json.NewDecoder(r.Body).Decode(&requestBody)
		if err != nil {
			http.Error(w, "Failed to decode JSON data", http.StatusBadRequest)
			return
		}

		blockchainAddress := requestBody.BlockchainAddress
		var publicKey string //, privateKey string
		err = db.QueryRow("SELECT pub_key FROM patiens WHERE blockchain_address = ?", blockchainAddress).Scan(&publicKey)
		if err != nil {
			http.Error(w, "Failed to retrieve public key from database", http.StatusInternalServerError)
			return
		}
		filetobeEncrypted := requestBody.FiletobeEncrypted
		fmt.Println("this is the file to be encrypted", string(filetobeEncrypted))

		decryptPubKey, _ := keygenD.GetAESDecrkeyypted(publicKey)

		decc := string(decryptPubKey)
		publicKeys, oks := keygenD.ParseECDSAPublicKey(decc)
		if oks != nil {
			fmt.Println(oks)
		}

		fmt.Println("this is the public key yeaaaaah", publicKeys)
		cipherText, capsule, err := recrypt.Encrypt(string(filetobeEncrypted), publicKeys)
		if err != nil {
			fmt.Println(err)
		}

		/*fmt.Println("capsule before encode:", capsule)

		fmt.Println("this is the encrypted file", cipherText)
		//capsule  asbytes

		plainTextByMyPri, err := recrypt.DecryptOnMyPriKey(privateKeys, capsule, cipherText)
		if err != nil {
			fmt.Println(err)
		}*/

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(models.RequestfileDEnc{
			EncryptedFile: cipherText,
			Capsule:       capsule,
		})
	}
}

func Decryptfile(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var requestBody models.RequestfileDEncfile
		err := json.NewDecoder(r.Body).Decode(&requestBody)
		if err != nil {
			http.Error(w, "Failed to decode JSON data", http.StatusBadRequest)
			return
		}
		fmt.Println("this is the request body:", requestBody)
		fmt.Println("this is the blockchain address:", string(requestBody.BlockchainAddress))
		fmt.Println("this is the encrypted file:", string(requestBody.EncryptedFile))
		fmt.Println("this is the capsule:", string(requestBody.Capsule))

		blockchainAddress := requestBody.BlockchainAddress
		var privateKey string
		err = db.QueryRow("SELECT priv_key FROM patiens WHERE blockchain_address = ?", blockchainAddress).Scan(&privateKey)
		if err != nil {
			http.Error(w, "Failed to retrieve private key from database", http.StatusInternalServerError)
			return
		}

		decryptPrivKey, _ := keygenD.GetAESDecrkeyypted(privateKey)
		decc := string(decryptPrivKey)
		privateKeys, oks := keygenD.ParseECDSAPrivateKey(decc)
		if oks != nil {
			fmt.Println(oks)
		}
		fmt.Println("this is the private key yeaaaaah", privateKeys)
		encryptedFile := requestBody.EncryptedFile
		capsule := requestBody.Capsule

		//fmt.Println("this is the capsule json", capsule)
		cc, errr := keygenD.ParseCapsule(capsule)
		if errr != nil {
			fmt.Println(errr)
		}
		fmt.Println("this is the capsule", cc)
		fmt.Println("this is the encrypted file", string(encryptedFile))
		plainTextByMyPri, err := recrypt.DecryptOnMyPriKey(privateKeys, cc, encryptedFile)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println("this is the decrypted file", string(plainTextByMyPri))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(models.RequestfileDEncfile2{
			BlockchainAddress: blockchainAddress,
			Decryptedfile:     json.RawMessage(plainTextByMyPri),
		})

	}
}
func Giveaccess(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var requestBody models.RequestAccess
		if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
			http.Error(w, "Failed to parse request body", http.StatusBadRequest)
			return
		}
		blockchainAddress := requestBody.BlockchainAddress
		bPubKey := requestBody.UserPubkey

		fmt.Println("this is the blockchain address", blockchainAddress)
		//// Check if patient already has a key
		var privateKey string
		err := db.QueryRow("SELECT priv_key FROM patiens WHERE blockchain_address = ?", blockchainAddress).Scan(&privateKey)
		if err == sql.ErrNoRows {

			http.Error(w, "No private key found for this patient", http.StatusBadRequest)

		}
		privateKeys, _ := keygenD.GetAESDecrkeyypted(privateKey)
		fmt.Println("this is the private key", string(privateKeys))
		privateKeyss, _ := keygenD.ParseECDSAPrivateKey(string(privateKeys))
		fmt.Println("this is the private keys", privateKeyss)
		bPubKeys, _ := keygenD.ParseECDSAPublicKey(bPubKey)
		fmt.Println("this is the public keys", bPubKeys)
		rk, pubX, err := recrypt.ReKeyGen(privateKeyss, bPubKeys)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println("rk:", rk)
		fmt.Println("pubX:", pubX)
		//convert rk and pubx to string
		rks := fmt.Sprintf("%v", rk)
		pubXs := fmt.Sprintf("%v", pubX)
		key := models.ReKeyGen{
			Regenkey: rks,
			PubX:     pubXs,
		}
		KeyTbeSent := models.NewRegenKeys{
			PatientAddress: blockchainAddress,
			UserAddress:    requestBody.UserAddress,
			Regenkey:       key,
		}
		res, err := SendRegenKeyToProxy(KeyTbeSent)
		if err != nil {
			fmt.Println(err)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(res)
	}

}

func SendRegenKeyToProxy(jsonData models.NewRegenKeys) (string, error) {

	JsonData, err := json.Marshal(jsonData)
	if err != nil {
		fmt.Println("Error marshalling JSON:", err)
		return "", err
	}
	fmt.Println("this is the json data", string(JsonData))

	resp, err := http.Post("http://localhost:8082/saveRKey", "application/json", bytes.NewBuffer(JsonData))
	if err != nil {
		fmt.Println("Error sending regen key to proxy:", err)
		return "", err
	}

	defer resp.Body.Close()

	return resp.Status, nil
}
func RegenKeyAdd(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var msg models.NewRegenKeys
		fmt.Println("RegenKeyAdd handler invoked")

		// Decode the JSON request body into the msg struct
		if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
			http.Error(w, "Failed to parse request body: "+err.Error(), http.StatusBadRequest)
			fmt.Println("Error decoding request body:", err)
			return
		}

		// Log the received message
		fmt.Printf("Received new regen key: %+v\n", msg.Regenkey)

		// Check if the row already exists in the database
		var id int
		err := db.QueryRow("SELECT id FROM proxysavekeys WHERE patient_address = ? AND user_address = ?", msg.PatientAddress, msg.UserAddress).Scan(&id)
		if err == sql.ErrNoRows {
			// If no rows exist, insert the new record into the database
			_, err := db.Exec("INSERT INTO proxysavekeys (patient_address, user_address, regenkey, pubX) VALUES (?, ?, ?, ?)",
				msg.PatientAddress, msg.UserAddress, msg.Regenkey.Regenkey, msg.Regenkey.PubX) // Serialize regenKey and PubX as needed
			if err != nil {
				http.Error(w, "Failed to store key pair in database: "+err.Error(), http.StatusInternalServerError)
				fmt.Println("Error storing key pair in database:", err)
				return
			}
		} else if err != nil {
			// Handle other errors from the database query
			http.Error(w, "Error querying database: "+err.Error(), http.StatusInternalServerError)
			fmt.Println("Error querying database:", err)
			return
		} else {
			// If the row already exists, return a conflict error
			http.Error(w, "Key pair already exists in database", http.StatusConflict)
			fmt.Println("Key pair already exists in database")
			return
		}

		// Respond to the request indicating success
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Regen key received successfully")
	}
}
func RegenKeyDelete(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var msg models.DeleteRequest
		if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
			http.Error(w, "Failed to decode JSON data: "+err.Error(), http.StatusBadRequest)
			fmt.Println("Error decoding JSON data:", err)
			return
		}

		// Log the received message
		fmt.Printf("Deleted regen key: %+v\n", msg)

		// Execute the DELETE SQL statement to remove the row from the database
		result, err := db.Exec("DELETE FROM proxysavekeys WHERE patient_address = ? AND user_address = ?", msg.PatientAddress, msg.UserAddress)
		if err != nil {
			http.Error(w, "Failed to delete regen key: "+err.Error(), http.StatusInternalServerError)
			fmt.Println("Error deleting regen key:", err)
			return
		}

		// Check if any rows were affected by the delete operation
		rowsAffected, err := result.RowsAffected()
		if err != nil {
			http.Error(w, "Failed to determine rows affected: "+err.Error(), http.StatusInternalServerError)
			fmt.Println("Error determining rows affected:", err)
			return
		}

		// If no rows were affected, it means the record didn't exist in the database
		if rowsAffected == 0 {
			http.Error(w, "Regen key not found in database", http.StatusNotFound)
			fmt.Println("Regen key not found in database")
			return
		}

		// Respond to the request indicating success
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Regen key deleted successfully")
	}
}
func Removeaccess(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var msg models.DeleteRequest
		if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		fmt.Println("Deleted regen key: %s\n", msg)
		JsonData, err := json.Marshal(msg)
		if err != nil {
			fmt.Println("Error marshalling JSON:", err)

		}
		fmt.Println("this is the json data", string(JsonData))

		resp, err := http.Post("http://localhost:8082/RemoveKey", "application/json", bytes.NewBuffer(JsonData))
		if err != nil {
			fmt.Println("Error sending regen key to proxy:", err)
		}

		defer resp.Body.Close()

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Regen key deleted")
	}
}
func RenEncryptionCipher(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var msg models.RenEncCipher

		if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		fmt.Println("RenEncryptionCipher handler invoked", msg)
		var pubXx string
		var rkStr string
		var rk big.Int
		p := msg.PatientUser.PatientAddress
		u := msg.PatientUser.UserAddress
		//fmt.Println("Patient address:", p, "User address:", u)
		// Query the database to retrieve the re-encryption key and public key
		err := db.QueryRow("SELECT regenkey,pubx FROM proxysavekeys WHERE  patient_address=? and user_address = ? ", p, u).Scan(&rkStr, &pubXx)
		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, "Re-encryption cipher not found", http.StatusNotFound)
			} else {
				http.Error(w, "Failed to retrieve re-encryption cipher from database", http.StatusInternalServerError)
			}
			return
		}

		//change rk to big.Int

		rk.SetString(rkStr, 10)
		// Parse the re-encryption key
		//fmt.Println("rk:", rkStr)
		// Parse the capsule data
		capsule := msg.CapsuleData
		capsules, _ := keygenD.ParseCapsule(capsule)
		fmt.Println("Capsules:", capsules)

		// Perform re-encryption
		NewCapsule, err := recrypt.ReEncryption(&rk, capsules)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		newCapsule, err := json.Marshal(NewCapsule)
		fmt.Println("NewCapsule:", string(newCapsule))
		// Respond with the new capsule and public key
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(models.NewCapsule{
			Capsule: newCapsule,
			Pubx:    pubXx,
		})
	}
}

func Decrypt(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var requestBody models.RenEncCipherText

		if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
			http.Error(w, "Failed to parse request body", http.StatusBadRequest)
			return
		}

		blockchainAddress := requestBody.NewCapsule.PatientUser.UserAddress
		// Retrieve the private key...
		// omitted for brevity
		fmt.Println("this is the blockchain address", blockchainAddress)
		// Check if patient already has a key
		var privateKey string
		err := db.QueryRow("SELECT  priv_key FROM users WHERE blockchain_address = ?", blockchainAddress).Scan(&privateKey)
		if err == sql.ErrNoRows {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		} else if err != nil {
			http.Error(w, "Failed to query database", http.StatusInternalServerError)
			return

		}

		jsonData, err := json.Marshal(requestBody.NewCapsule)
		if err != nil {
			fmt.Println("Error marshalling JSON:", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		fmt.Println("this is the json data", string(jsonData))
		resp, err := http.Post("http://localhost:8082/RenEncCipher", "application/json", bytes.NewBuffer(jsonData))
		if err != nil {
			fmt.Println("Error sending regen key to proxy:", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		bodyBytes, err := ioutil.ReadAll(resp.Body)
		//fmt.Println("this is the body bytes", string(bodyBytes))
		if err != nil {
			http.Error(w, "Failed to read server response", http.StatusInternalServerError)
			return
		}

		// Optional: Unmarshal and remarshal if you need to modify or selectively send data
		var data models.NewCapsule //Use a more specific type as needed
		if err := json.Unmarshal(bodyBytes, &data); err != nil {
			http.Error(w, "Failed to process server response", http.StatusInternalServerError)
			return
		}
		privateKeys, _ := keygenD.GetAESDecrkeyypted(privateKey)
		UprivateKey, _ := keygenD.ParseECDSAPrivateKey(string(privateKeys))
		NewCapsule, _ := keygenD.ParseCapsuleOriginal(data.Capsule)
		pubx, _ := keygenD.ParseECDSAPublicKey(data.Pubx)

		fmt.Println("this is the capsule", NewCapsule, "this is the public key", pubx, "this is the private key", UprivateKey, "this is the cipher", string(requestBody.TestCiphers))
		plainText, err := recrypt.Decrypt(UprivateKey, NewCapsule, pubx, requestBody.TestCiphers)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println("this is the plain text", string(plainText))

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(models.RequestfileDEncfile2{
			BlockchainAddress: blockchainAddress,
			Decryptedfile:     plainText,
		}); err != nil {
			http.Error(w, "Failed to send response", http.StatusInternalServerError)
		}

	}
}
func SaveUser(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var requestBody models.RequestBody
		if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
			http.Error(w, "Failed to parse request body", http.StatusBadRequest)
			return
		}
		blockchainAddress := requestBody.BlockchainAddress
		fmt.Println("this is the blockchain address", blockchainAddress)
		// Check if patient already has a key
		var publicKey, privateKey string
		err := db.QueryRow("SELECT pub_key, priv_key FROM users WHERE blockchain_address = ?", blockchainAddress).Scan(&publicKey, &privateKey)
		if err == sql.ErrNoRows {

			aPriKey, aPubKey, _ := curve.GenerateKeys()
			publicKey = fmt.Sprintf("%v", aPubKey)  // Convert bytes to string
			privateKey = fmt.Sprintf("%v", aPriKey) // Convert aPriKey to string
			encryptedPubKey, _ := keygenD.GetAESEncrypted(publicKey)
			encryptedPriKey, _ := keygenD.GetAESEncrypted(privateKey)
			//	publicKey = fmt.Sprintf("%v", encryptedPubKey) // Convert bytes to string
			//	privateKey = fmt.Sprintf("%v", encryptedPriKey)
			fmt.Println("this is the public key", publicKey)
			fmt.Println("this is the private key", privateKey)
			fmt.Println("this is the encrypted public key", encryptedPubKey)
			fmt.Println("this is the encrypted private key", encryptedPriKey)
			_, err := db.Exec("INSERT INTO users (blockchain_address, pub_key, priv_key) VALUES (?, ?, ?)", blockchainAddress, encryptedPubKey, encryptedPriKey)
			if err != nil {
				http.Error(w, "Failed to store key pair in database", http.StatusInternalServerError)
				return
			}

			keys := struct {
				PublicKey string `json:"public_key"`
			}{
				PublicKey: publicKey,
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(keys)

		} else if err != nil {
			http.Error(w, "Failed to query database", http.StatusInternalServerError)
			return
		}
	}
}
