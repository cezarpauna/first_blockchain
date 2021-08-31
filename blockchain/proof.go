package blockchain

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log"
	"math"
	"math/big"
)

const Difficulty = 16

// Proof of Work struct
// pointer to a block to show that the work was done
// pointer to a target int
type Proof struct {
	Block  *Block
	Target *big.Int
}

// Helper function for returing a new Proof struct
// For a given block returns a Proof
func NewProof(block *Block) *Proof {
	// generate target for the proof of work algorithm by left shifting with 256-Difficulty
	target := big.NewInt(1)
	target.Lsh(target, uint(256-Difficulty))

	return &Proof{block, target}
}

// Helper function for transforming int64 to hex
func ToHex(number int64) []byte {
	buffer := new(bytes.Buffer)
	err := binary.Write(buffer, binary.BigEndian, number)
	if err != nil {
		log.Panic(err)
	}

	return buffer.Bytes()
}

func StringToHex(data string) []byte {
	return []byte(data)
}

// We need to have all the data that will be hashed for the proof of work
func (pow *Proof) GetData(nonce int) []byte {
	data := bytes.Join(
		[][]byte{
			pow.Block.PrevHash,
			pow.Block.HashTransactions(),
			ToHex(int64(nonce)),
			ToHex(int64(Difficulty)),
		},
		[]byte{},
	)

	return data
}

// incrementing the nonce until the desired hash is fund
func (pow *Proof) RunPoWAlg() (int, []byte) {
	var checkHash big.Int
	var hash [32]byte

	nonce := 0

	for nonce < math.MaxInt64 {
		data := pow.GetData(nonce)
		hash = sha256.Sum256(data)

		fmt.Printf("\r%x", hash)
		checkHash.SetBytes(hash[:])

		if checkHash.Cmp(pow.Target) == -1 {
			break
		} else {
			nonce++
		}

	}
	fmt.Println()

	return nonce, hash[:]
}

// Helper function for validating an existing proof of work
func (pow *Proof) ValidatePoW() bool {
	data := pow.GetData(pow.Block.Nonce)

	hash := sha256.Sum256(data)
	checkHash := big.NewInt(0).SetBytes(hash[:])

	return checkHash.Cmp(pow.Target) == -1
}
