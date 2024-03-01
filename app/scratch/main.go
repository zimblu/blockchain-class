package main

import (
	"encoding/json"
	"fmt"
	"log"

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
		FromID:  "bill",
		ToValue: "zimblu",
		Value:   10000,
	}
	data, err := json.Marshal(tx)
	if err != nil {
		fmt.Errorf("unable to Marshal: %w", err)
	}
	v := crypto.Keccak256(data)

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

	return nil
}
