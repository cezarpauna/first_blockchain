package wallet

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"log"

	"github.com/mr-tron/base58/base58"
	"golang.org/x/crypto/ripemd160"
)

const (
	checksumLength = 4
	version        = byte(0x00)
)

func Base58Encode(input []byte) []byte {
	encode := base58.Encode(input)

	return []byte(encode)
}

func Base58Decode(input []byte) []byte {
	decode, err := base58.Decode(string(input[:]))
	if err != nil {
		log.Panic(err)
	}

	return decode
}

// a wallet is a structure containing a pair of public and private keys
// with these keys we can access the availabele outputs for transactions
type Wallet struct {
	PrivateKey ecdsa.PrivateKey
	PublicKey  []byte
}

// Using the ecsdsa module we can generate a private key by giving an elipitic curve (256 bits) and a random number
func NewKeyPair() (ecdsa.PrivateKey, []byte) {
	curve := elliptic.P256()
	private, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		log.Panic(err)
	}
	// append X values and Y values into a public key
	pub := append(private.PublicKey.X.Bytes(), private.PublicKey.Y.Bytes()...)
	return *private, pub
}

// Inititate the Wallet structure
func MakeWallet() *Wallet {
	private, public := NewKeyPair()
	return &Wallet{private, public}
}

// For a public key hash we need to hash the pubkey and then run a ripemd160 hashing function on the hashed key
func PublicKeyHash(pubKey []byte) []byte {
	pubHash := sha256.Sum256(pubKey)

	hasher := ripemd160.New()
	_, err := hasher.Write(pubHash[:])
	if err != nil {
		log.Panic(err)
	}

	publicRipMD := hasher.Sum(nil)

	return publicRipMD
}

func Checksum(key []byte) []byte {
	firstHash := sha256.Sum256(key)
	secondHash := sha256.Sum256(firstHash[:])
	return secondHash[:checksumLength]
}

// Generate the address of a wallet
// For the address we need a public key hash a version and a checksum
// the public key hash is a sha256 hash followed by a ripemd160
// for the checksum we use sha256 two times and return the first checksumlength bytes
// we append all together and then run a Base58 encode for the final address
func (wallet Wallet) Address() []byte {
	pubHash := PublicKeyHash(wallet.PublicKey)
	versionedHash := append([]byte{version}, pubHash...)
	checksum := Checksum(versionedHash)
	fullHash := append(versionedHash, checksum...)
	address := Base58Encode(fullHash)
	return address
}

func ValidateAddress(address string) bool {
	pubKeyHash := Base58Decode([]byte(address))
	actualChecksum := pubKeyHash[len(pubKeyHash)-checksumLength:]
	version := pubKeyHash[0]
	pubKeyHash = pubKeyHash[1 : len(pubKeyHash)-checksumLength]
	targetChecksum := Checksum(append([]byte{version}, pubKeyHash...))

	return bytes.Compare(actualChecksum, targetChecksum) == 0
}
