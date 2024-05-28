package keygenD

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"fmt"
	"goRecrypt/recrypt"
	"math/big"
	"strconv"
	"strings"
)

func ParseByteString(byteStr string) ([]byte, error) {
	// Remove brackets and split by space
	byteStr = strings.TrimPrefix(byteStr, "[")
	byteStr = strings.TrimSuffix(byteStr, "]")
	byteSliceStr := strings.Split(byteStr, " ")

	// Convert string values to bytes
	byteSlice := make([]byte, len(byteSliceStr))
	for i, byteStr := range byteSliceStr {
		byteValue, err := strconv.Atoi(byteStr)
		if err != nil {
			return nil, fmt.Errorf("error converting string to byte: %v", err)
		}
		byteSlice[i] = byte(byteValue)
	}

	return byteSlice, nil
}
func ParseECDSAPrivateKey(privateKeyString string) (*ecdsa.PrivateKey, error) {
	// Extract components of the private key string
	privateKeyString = strings.TrimPrefix(privateKeyString, "&{")
	//	fmt.Println("this is the private key string", privateKeyString)
	parts := strings.Split(privateKeyString, " ")
	//	fmt.Println("this is the parts", parts)
	if len(parts) != 4 {
		return nil, errors.New("invalid private key string format")
	}

	x, ok := new(big.Int).SetString(parts[1], 10)
	if !ok {
		return nil, errors.New("failed to parse X component of private key")
	}
	dss := parts[2]
	ds := strings.TrimSuffix(dss, "}")
	//	fmt.Println("this is the ds", ds)
	y, ok := new(big.Int).SetString(ds, 10)
	if !ok {
		return nil, errors.New("failed to parse Y component of private key")
	}
	ddd := parts[3]
	dd := strings.TrimSuffix(ddd, "}")
	d, ok := new(big.Int).SetString(dd, 10)
	if !ok {
		return nil, errors.New("failed to parse D component of private key")
	}

	// Create the ECDSA private key
	privateKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(), // Assuming P-256 curve
			X:     x,
			Y:     y,
		},
		D: d,
	}

	return privateKey, nil
}

func ParseECDSAPublicKey(publicKeyString string) (*ecdsa.PublicKey, error) {
	// Extract components of the public key string
	deccc := strings.TrimPrefix(publicKeyString, "&{")
	publicKeyString = strings.TrimSuffix(deccc, "}")
	//fmt.Println("this is the public key string", publicKeyString)
	parts := strings.Split(publicKeyString, " ")
	//fmt.Println("this is the parts", parts)
	if len(parts) != 3 {
		return nil, errors.New("invalid public key string format")
	}

	x, ok := new(big.Int).SetString(parts[1], 10)
	if !ok {
		return nil, errors.New("failed to parse X component of public key")
	}

	y, ok := new(big.Int).SetString(parts[2], 10)
	if !ok {
		return nil, errors.New("failed to parse Y component of public key")
	}

	// Create the ECDSA public key
	publicKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(), // Assuming P-256 curve
		X:     x,
		Y:     y,
	}

	return publicKey, nil
}

func ParseCapsuleOriginal(capsuleJSON []byte) (*recrypt.Capsule, error) {
	var capsuleData struct {
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

	// Unmarshal the JSON into the capsuleData struct
	if err := json.Unmarshal(capsuleJSON, &capsuleData); err != nil {
		return nil, err
	}

	// Parse E public key
	ePublicKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     capsuleData.E.X,
		Y:     capsuleData.E.Y,
	}

	// Parse V public key
	vPublicKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     capsuleData.V.X,
		Y:     capsuleData.V.Y,
	}

	// Create the recrypt.Capsule object
	capsule := &recrypt.Capsule{
		E: ePublicKey,
		V: vPublicKey,
		S: capsuleData.S,
	}

	return capsule, nil
}

func ParseCapsule(capsuleJSON []byte) (*recrypt.Capsule, error) {
	var capsuleData struct {
		E struct {
			Curve any    `json:"Curve"`
			X     string `json:"X"`
			Y     string `json:"Y"`
		} `json:"E"`
		V struct {
			Curve any    `json:"Curve"`
			X     string `json:"X"`
			Y     string `json:"Y"`
		} `json:"V"`
		S string `json:"S"`
	}

	// Unmarshal the JSON into the capsuleData struct
	if err := json.Unmarshal(capsuleJSON, &capsuleData); err != nil {
		return nil, err
	}

	// Parse X and Y values of E
	eX, ok := new(big.Int).SetString(capsuleData.E.X, 10)
	if !ok {
		return nil, fmt.Errorf("failed to parse X value of E")
	}
	eY, ok := new(big.Int).SetString(capsuleData.E.Y, 10)
	if !ok {
		return nil, fmt.Errorf("failed to parse Y value of E")
	}

	// Parse X and Y values of V
	vX, ok := new(big.Int).SetString(capsuleData.V.X, 10)
	if !ok {
		return nil, fmt.Errorf("failed to parse X value of V")
	}
	vY, ok := new(big.Int).SetString(capsuleData.V.Y, 10)
	if !ok {
		return nil, fmt.Errorf("failed to parse Y value of V")
	}

	// Parse S value
	s, ok := new(big.Int).SetString(capsuleData.S, 10)
	if !ok {
		return nil, fmt.Errorf("failed to parse S value")
	}

	// Create the recrypt.Capsule object
	capsule := &recrypt.Capsule{
		E: &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     eX,
			Y:     eY,
		},
		V: &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     vX,
			Y:     vY,
		},
		S: s,
	}

	return capsule, nil
}
