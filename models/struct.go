package models

import (
	"encoding/json"
	"goRecrypt/recrypt"
	"math/big"
)

type RenEncCipherText struct {
	NewCapsule  RenEncCipher `json:"Capsule"`
	TestCiphers []byte       `json:"TextCipher"`
}
type RenEncCipher struct {
	PatientUser DeleteRequest   `json:"patient_user"`
	CapsuleData json.RawMessage `json:"capsule_data"`
}
type DeleteRequest struct {
	PatientAddress string `json:"patient_address"`
	UserAddress    string `json:"user_address"`
}
type NewCapsule struct {
	Capsule json.RawMessage `json:"capsule"`
	Pubx    string          `json:"pubx"`
}

type RegenKeyMessage struct {
	NewRegenKey string `json:"new_regenkey"`
}
type RequestBody struct {
	BlockchainAddress string `json:"blockchain_address"`
}

type RequestfileEnc struct {
	BlockchainAddress string          `json:"blockchain_address"`
	FiletobeEncrypted json.RawMessage `json:"file_to_be_encrypted"`
}

type RequestfileDEnc struct {
	EncryptedFile []byte           `json:"encrypted_file"`
	Capsule       *recrypt.Capsule `json:"capsule"`
}

type RequestAccess struct {
	BlockchainAddress string `json:"blockchain_address"`
	UserAddress       string `json:"user_address"`
	UserPubkey        string `json:"user_pubkey"`
}
type NewRegenKeys struct {
	PatientAddress string   `json:"patient_address"`
	UserAddress    string   `json:"user_address"`
	Regenkey       ReKeyGen `json:"regenkey"`
}

type ReKeyGen struct {
	Regenkey string `json:"Genkey"`
	PubX     string `json:"pubX"`
}
type RequestfileDEncfile struct {
	BlockchainAddress string          `json:"blockchain_address"`
	EncryptedFile     []byte          `json:"encrypted_file"`
	Capsule           json.RawMessage `json:"capsule"`
}
type RequestfileDEncfile2 struct {
	BlockchainAddress string          `json:"blockchain_address"`
	Decryptedfile     json.RawMessage `json:"decrypted_file"`
}

type capsuleData struct {
	E struct {
		Curve any      `json:"Curve"`
		X     *big.Int `json:"X"`
		Y     *big.Int `json:"Y"`
	} `json:"E"`
	V struct {
		Curve any      `json:"Curve"`
		X     *big.Int `json:"X"`
		Y     *big.Int `json:"Y"`
	} `json:"V"`
	S *big.Int `json:"S"`
}
