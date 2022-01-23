package ethscrow

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"math/big"
	"syscall/js"
)

func encodeToString(arr []byte) string {
	return hex.EncodeToString(arr)
}

func decodeToString(s string) []byte {
	arr, err := hex.DecodeString(s)
	if err != nil {
		return nil
	}
	return arr
}

func GenerateKeyPair(this js.Value, args []js.Value) interface{} {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		fmt.Println(err)
		return nil
	}

	return js.ValueOf(
		map[string]interface{}{
			"privateKey": encodeToString(privKeyBytes),
			"publicKey":  encodeToString(pubKeyBytes),
		})
}

func getPrivateKey(key string) *ecdsa.PrivateKey {
	privateKeyHex := decodeToString(key)

	privateKey, err := x509.ParsePKCS8PrivateKey(privateKeyHex)
	if err != nil {
		return nil
	}

	return privateKey.(*ecdsa.PrivateKey)
}

func getPublicKey(key string) *ecdsa.PublicKey {
	publicKeyHex := decodeToString(key)

	publicKey, err := x509.ParsePKIXPublicKey(publicKeyHex)
	if err != nil {
		return nil
	}

	return publicKey.(*ecdsa.PublicKey)
}

func Sign(this js.Value, args []js.Value) interface{} {
	privateKey := getPrivateKey(args[0].String())
	data := args[1].String()

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, []byte(data))
	if err != nil {
		return nil
	}

	return js.ValueOf(map[string]interface{}{
		"r": r.String(),
		"s": s.String(),
	})
}

func Encrypt(this js.Value, args []js.Value) interface{} {
	publicKey := getPublicKey(args[0].String())

	k, err := rand.Int(rand.Reader, new(big.Int).SetBytes([]byte("FFFFFFFFFFFF")))
	if err != nil {
		return nil
	}

	c2x, c2y := publicKey.Curve.ScalarMult(publicKey.X, publicKey.Y, publicKey.Curve.Params().Gx.Bytes())
	c1x, c1y := publicKey.Curve.ScalarBaseMult(k.Bytes())

	return js.ValueOf(map[string]interface{}{
		"c1": elliptic.Marshal(publicKey.Curve, c1x, c1y),
		"c2": elliptic.Marshal(publicKey.Curve, c2x, c2y),
	})
}

func Decrypt(this js.Value, args []js.Value) interface{} {
	privateKey := getPrivateKey(args[0].String())

	c1x, c1y := elliptic.Unmarshal(privateKey.Curve, []byte(args[1].String()))
	c2x, c2y := elliptic.Unmarshal(privateKey.Curve, []byte(args[2].String()))

	subX, subY := privateKey.Curve.ScalarMult(c1x, c1y, privateKey.D.Bytes())

	msg, _ := privateKey.Curve.Add(c2x, c2y, subX, new(big.Int).Neg(subY))

	return js.ValueOf(msg.String())
}
