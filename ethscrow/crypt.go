package ethscrow

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"syscall/js"
)

func encodeToString(arr []byte) string {
	return hex.EncodeToString(arr)
}

func GenerateKeyPair(this js.Value, args []js.Value) interface{} {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	privKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		fmt.Println(err)
		return nil
	}

	return map[string]interface{}{
		"privateKey": encodeToString(privKeyBytes),
		"publicKey":  encodeToString(pubKeyBytes),
	}
}

func PEMtoHex(this js.Value, args []js.Value) interface{} {
	
	return nil
}
