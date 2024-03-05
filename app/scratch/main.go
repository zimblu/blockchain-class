package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

type Tx struct {
	FromID  string `json:"from"`
	ToValue string `json:"to"`
	Value   uint64 `json:"value"`
}

func main() {
	if err := run(); err != nil {
		log.Fatalln(err)
	}
}

func run() error {
	privateKey, err := crypto.LoadECDSA("zblock/accounts/kennedy.ecdsa")
	if err != nil {
		fmt.Errorf("unable to load privatekey to node: %w", err)
	}

	tx := Tx{
		FromID:  "0xF01813E4B85e178A83e29B8E7bF26BD830a25f32",
		ToValue: "zimblu",
		Value:   10000,
	}
	data, err := json.Marshal(tx)
	if err != nil {
		fmt.Errorf("unable to Marshal: %w", err)
	}

	stamp := []byte(fmt.Sprintf("\x19Ardan Signed Message:\n%d", len(data)))

	v := crypto.Keccak256(stamp, data)

	sig, err := crypto.Sign(v, privateKey)
	if err != nil {
		fmt.Errorf("unable to sign: %w", err)
	}
	fmt.Println("SIG:", hexutil.Encode(sig))
	// =========================================================
	// OVER THE WIRE

	publicKey, err := crypto.SigToPub(v, sig)
	if err != nil {
		return fmt.Errorf("unable to pub: %w", err)
	}

	fmt.Println("PUB:", crypto.PubkeyToAddress(*publicKey).String())

	// ================================================================

	tx = Tx{
		FromID:  "0xF01813E4B85e178A83e29B8E7bF26BD830a25f32",
		ToValue: "frank",
		Value:   250,
	}
	data, err = json.Marshal(tx)
	if err != nil {
		fmt.Errorf("unable to Marshal: %w", err)
	}
	stamp = []byte(fmt.Sprintf("\x19Ardan Signed Message:\n%d", len(data)))
	v2 := crypto.Keccak256(stamp, data)

	sig2, err := crypto.Sign(v2, privateKey)
	if err != nil {
		fmt.Errorf("unable to sign: %w", err)
	}
	fmt.Println("SIG:", hexutil.Encode(sig2))

	// ====================================================
	// OVER THE WIRE

	tx2 := Tx{
		FromID:  "0xF01813E4B85e178A83e29B8E7bF26BD830a25f32",
		ToValue: "frank",
		Value:   250,
	}

	data, err = json.Marshal(tx2)
	if err != nil {
		fmt.Errorf("unable to Marshal: %w", err)
	}
	stamp = []byte(fmt.Sprintf("\x19Ardan Signed Message:\n%d", len(data)))
	v2 = crypto.Keccak256(stamp, data)

	publicKey, err = crypto.SigToPub(v2, sig2)
	if err != nil {
		return fmt.Errorf("unable to pub: %w", err)
	}

	fmt.Println("PUB:", crypto.PubkeyToAddress(*publicKey).String())

	vv, r, s, err := ToVRSFromHexSignature(hexutil.Encode(sig2))
	if err != nil {
		return fmt.Errorf("unable to VRS: %w", err)
	}

	fmt.Println("V|R|S", vv, r, s)
	return nil
}

// ToVRSFromHexSignature converts a hex representation of the signature into
// its R, S and V parts.

func ToVRSFromHexSignature(sigStr string) (v, r, s *big.Int, err error) {
	sig, err := hex.DecodeString(sigStr[2:])
	if err != nil {
		return nil, nil, nil, err
	}

	r = big.NewInt(0).SetBytes(sig[:32])
	s = big.NewInt(0).SetBytes(sig[32:64])
	v = big.NewInt(0).SetBytes([]byte{sig[64]})

	return v, r, s, nil
}
