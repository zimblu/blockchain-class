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
	tx := Tx{
		FromID:  "bill",
		ToValue: "zimblu",
		Value:   10000,
	}

	privateKey, err := crypto.LoadECDSA("zblock/accounts/kennedy.ecdsa")
	if err != nil {
		fmt.Errorf("unable to load privatekey to node: %w", err)
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
	fmt.Println(hexutil.Encode(sig))
	fmt.Println(string(sig))
	return nil
}
