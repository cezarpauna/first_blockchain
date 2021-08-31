package wallet

import (
	"bytes"
	"crypto/elliptic"
	"encoding/gob"
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

// For the moment we use a file for storing wallet information
const walletFile = "./tmp/wallets.data"

type Wallets struct {
	Wallets map[string]*Wallet
}

func (wallets Wallets) LoadFile() error {
	if _, err := os.Stat(walletFile); os.IsNotExist(err) {
		return err
	}

	var ws Wallets
	file, err := ioutil.ReadFile(walletFile)
	if err != nil {
		return err
	}
	gob.Register(elliptic.P256())
	decoder := gob.NewDecoder(bytes.NewReader(file))
	err = decoder.Decode(&wallets)
	if err != nil {
		return err
	}
	wallets.Wallets = ws.Wallets
	return nil
}

func (wallets *Wallets) SaveFile() {
	var content bytes.Buffer
	gob.Register(elliptic.P256())
	encoder := gob.NewEncoder(&content)
	err := encoder.Encode(wallets)
	if err != nil {
		log.Panic(err)
	}
	err = ioutil.WriteFile(walletFile, content.Bytes(), 0644)
	if err != nil {
		log.Panic(err)
	}
}

func CreateWallets() (*Wallets, error) {
	wallets := Wallets{}
	wallets.Wallets = make(map[string]*Wallet)
	err := wallets.LoadFile()
	return &wallets, err
}

func (wallets *Wallets) AddWallet() string {
	wallet := MakeWallet()
	address := fmt.Sprintf("%s", wallet.Address())
	wallets.Wallets[address] = wallet
	return address
}

func (wallets *Wallets) GetAllAdresses() []string {
	var addresses []string

	for address := range wallets.Wallets {
		addresses = append(addresses, address)
	}
	return addresses
}

func (wallets Wallets) GetWallet(address string) Wallet {
	return *wallets.Wallets[address]
}
