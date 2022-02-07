package ethscrow

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	eth "github.com/ethereum/go-ethereum/crypto"
	"math/big"
	"syscall/js"
)

func encodeToHexString(arr []byte) string {
	return hex.EncodeToString(arr)
}

func decodeToHex(s string) []byte {
	arr, err := hex.DecodeString(s)
	if err != nil {
		fmt.Println(err)
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
			"privateKey": encodeToHexString(privKeyBytes),
			"publicKey":  encodeToHexString(pubKeyBytes),
		})
}

func getPrivateKey(key string) *ecdsa.PrivateKey {
	privateKeyHex := decodeToHex(key)

	privateKey, err := x509.ParsePKCS8PrivateKey(privateKeyHex)
	if err != nil {
		fmt.Println(err)
		return nil
	}

	return privateKey.(*ecdsa.PrivateKey)
}

func getPublicKey(key string) *ecdsa.PublicKey {
	publicKeyHex := decodeToHex(key)

	publicKey, err := x509.ParsePKIXPublicKey(publicKeyHex)
	if err != nil {
		fmt.Println(err)
		return nil
	}

	return publicKey.(*ecdsa.PublicKey)
}

func Sign(this js.Value, args []js.Value) interface{} {
	privateKey := getPrivateKey(args[0].String())
	data, err := hex.DecodeString(args[1].String())

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, data)
	if err != nil {
		fmt.Println(err)
		return nil
	}

	return js.ValueOf(map[string]interface{}{
		"r": encodeToHexString(r.Bytes()),
		"s": encodeToHexString(s.Bytes()),
	})
}

func Encrypt(this js.Value, args []js.Value) interface{} {
	publicKey := getPublicKey(args[0].String())

	k, err := rand.Int(rand.Reader, new(big.Int).SetBytes([]byte("FFFFFFFFFFFF")))
	if err != nil {
		fmt.Println(err)
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

func GenerateThreshold(this js.Value, args []js.Value) interface{} {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Println(err)
		return nil
	}

	x, y := privateKey.ScalarBaseMult(privateKey.D.Bytes())

	return js.ValueOf(map[string]interface{}{
		"privateShare": encodeToHexString(privateKey.D.Bytes()),
		"publicShareX": encodeToHexString(x.Bytes()),
		"publicShareY": encodeToHexString(y.Bytes()),
	})
}

func GenerateEscrowAddress(this js.Value, args []js.Value) interface{} {
	aX, aY := decodeToHex(args[0].String()), decodeToHex(args[1].String())
	bX, bY := decodeToHex(args[2].String()), decodeToHex(args[3].String())

	x, y := elliptic.P256().Add(
		new(big.Int).SetBytes(aX),
		new(big.Int).SetBytes(aY),
		new(big.Int).SetBytes(bX),
		new(big.Int).SetBytes(bY),
	)

	key := &ecdsa.PublicKey{
		X:     x,
		Y:     y,
		Curve: elliptic.P256(),
	}

	return js.ValueOf(eth.PubkeyToAddress(*key).Hex())
}

func GenerateEscrowPrivateKey(this js.Value, args []js.Value) interface{} {
	aD, bD := decodeToHex(args[0].String()), decodeToHex(args[1].String())
	private := new(big.Int).Add(new(big.Int).SetBytes(aD), new(big.Int).SetBytes(bD))

	return js.ValueOf(encodeToHexString(private.Bytes()))
}
