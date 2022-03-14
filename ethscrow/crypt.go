package ethscrow

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/core/types"
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
		fmt.Printf("decodeToHex: %v", err)
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
	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey) // TODO: switch to  MarshalECPrivateKey
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
		fmt.Printf("getPublicKey: %v", err)
		return nil
	}

	return publicKey.(*ecdsa.PublicKey)
}

func Sign(this js.Value, args []js.Value) interface{} {
	privateKey := getPrivateKey(args[0].String())
	data := decodeToHex(args[1].String())

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, data)
	if err != nil {
		fmt.Printf("Sign: %v", err)
		return nil
	}

	return js.ValueOf(map[string]interface{}{
		"r": encodeToHexString(r.Bytes()),
		"s": encodeToHexString(s.Bytes()),
	})
}

func Encrypt(this js.Value, args []js.Value) interface{} {
	publicKey := getPublicKey(args[0].String())
	data := decodeToHex(args[1].String())

	k, err := rand.Int(rand.Reader, new(big.Int).SetBytes([]byte("FFFFFFFFFFFF")))
	if err != nil {
		fmt.Printf("Encrypt: %v", err)
		return nil
	}

	c2xHalf, c2yHalf := publicKey.Curve.ScalarMult(publicKey.X, publicKey.Y, k.Bytes())
	c1x, c1y := publicKey.Curve.ScalarBaseMult(k.Bytes())
	c2x, c2y := publicKey.Curve.Add(new(big.Int).SetBytes(data), new(big.Int).SetInt64(0), c2xHalf, c2yHalf)

	return js.ValueOf(map[string]interface{}{
		"c1x": encodeToHexString(c1x.Bytes()),
		"c1y": encodeToHexString(c1y.Bytes()),
		"c2x": encodeToHexString(c2x.Bytes()),
		"c2y": encodeToHexString(c2y.Bytes()),
	})
}

func Decrypt(this js.Value, args []js.Value) interface{} {
	privateKey := getPrivateKey(args[0].String())
	c1x, c1y := new(big.Int).SetBytes(decodeToHex(args[1].String())), new(big.Int).SetBytes(decodeToHex(args[2].String()))
	c2x, c2y := new(big.Int).SetBytes(decodeToHex(args[3].String())), new(big.Int).SetBytes(decodeToHex(args[4].String()))

	subX, subY := privateKey.Curve.ScalarMult(c1x, c1y, privateKey.D.Bytes())

	msg, _ := privateKey.Curve.Add(c2x, c2y, subX, new(big.Int).Neg(subY))

	return js.ValueOf(encodeToHexString(msg.Bytes()))
}

func GenerateThreshold(this js.Value, args []js.Value) interface{} {
	privateKey, err := ecdsa.GenerateKey(eth.S256(), rand.Reader)
	if err != nil {
		fmt.Printf("GenerateThreshold: %v", err)
		return nil
	}

	privInt := new(big.Int).SetBytes(privateKey.D.Bytes())
	xG := []int64{privateKey.PublicKey.X.Int64(), privateKey.PublicKey.Y.Int64()}
	G := []int64{privateKey.Curve.Params().Gx.Int64(), privateKey.Curve.Params().Gy.Int64()}

	v, _ := rand.Int(rand.Reader, new(big.Int).Sub(eth.S256().Params().N, new(big.Int).SetInt64(1)))
	vx, vy := privateKey.Curve.ScalarBaseMult(v.Bytes())
	h := md5.Sum([]byte(fmt.Sprintf("%v%v%v", G, privInt.Int64(), xG)))

	c := new(big.Int).SetBytes(h[:])
	r := new(big.Int).Mod(new(big.Int).Sub(v, new(big.Int).Mul(c, privInt)), privateKey.Curve.Params().N)

	x, y := privateKey.ScalarBaseMult(privateKey.D.Bytes())

	return js.ValueOf(map[string]interface{}{
		"privateShare": encodeToHexString(privateKey.D.Bytes()),
		"publicShareX": encodeToHexString(x.Bytes()),
		"publicShareY": encodeToHexString(y.Bytes()),
		"c":            encodeToHexString(c.Bytes()),
		"r":            encodeToHexString(r.Bytes()),
		"vGx":          encodeToHexString(vx.Bytes()),
		"vGy":          encodeToHexString(vy.Bytes()),
	})
}

func GenerateEscrowAddress(this js.Value, args []js.Value) interface{} {
	aX, aY := decodeToHex(args[0].String()), decodeToHex(args[1].String())
	bX, bY := decodeToHex(args[2].String()), decodeToHex(args[3].String())
	//c := decodeToHex(args[4].String())
	//r := decodeToHex(args[5].String())
	//vGx, vGy := decodeToHex(args[6].String()), decodeToHex(args[7].String())
	//
	bxInt, byInt := new(big.Int).SetBytes(bX), new(big.Int).SetBytes(bY)
	//
	//rGx, rGy := eth.S256().ScalarBaseMult(r)
	//cxG, cyG := eth.S256().ScalarMult(bxInt, byInt, c)
	//vCheckx, vChecky := eth.S256().Add(rGx, rGy, cxG, cyG)

	// TODO: Fix zkp
	//if vCheckx.Cmp(new(big.Int).SetBytes(vGx)) != 0 && vChecky.Cmp(new(big.Int).SetBytes(vGy)) != 0 {
	//	fmt.Println("The other user doesn't have the correct private key.")
	//	return js.ValueOf(nil)
	//}

	x, y := eth.S256().Add(
		new(big.Int).SetBytes(aX),
		new(big.Int).SetBytes(aY),
		bxInt,
		byInt,
	)

	key := &ecdsa.PublicKey{
		X:     x,
		Y:     y,
		Curve: eth.S256(),
	}

	return js.ValueOf(eth.PubkeyToAddress(*key).Hex())
}

func GenerateEscrowPrivateKey(this js.Value, args []js.Value) interface{} {
	aD, bD := decodeToHex(args[0].String()), decodeToHex(args[1].String())
	private := new(big.Int).Mod(new(big.Int).Add(new(big.Int).SetBytes(aD), new(big.Int).SetBytes(bD)), eth.S256().Params().N)

	return js.ValueOf(encodeToHexString(private.Bytes()))
}

func SignEthTx(this js.Value, args []js.Value) interface{} {
	tx := new(types.Transaction)
	err := tx.UnmarshalJSON([]byte(args[0].String()))
	if err != nil {
		fmt.Printf("SignEthTx-unmarshal: %v", err)
		return nil
	}

	privateKey, err := eth.HexToECDSA(args[2].String())
	if err != nil {
		fmt.Printf("SignEthTx-HexToECDSA: %v", err)
		return nil
	}

	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(new(big.Int).SetInt64(int64(args[1].Int()))), privateKey)
	if err != nil {
		fmt.Printf("SignEthTx-signing: %v", err)
		return nil
	}

	signedTxJson, err := signedTx.MarshalJSON()
	if err != nil {
		fmt.Println("rlp encoding error.")
		return nil
	}

	return js.ValueOf(string(signedTxJson))
}
