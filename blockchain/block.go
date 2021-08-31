package blockchain

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	mrand "math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/davecgh/go-spew/spew"
	libp2p "github.com/libp2p/go-libp2p"
	net1 "github.com/libp2p/go-libp2p-core/network"
	crypto "github.com/libp2p/go-libp2p-crypto"
	host "github.com/libp2p/go-libp2p-host"
	"github.com/libp2p/go-libp2p/examples/p2p/wallet"
	ma "github.com/multiformats/go-multiaddr"
)

const (
	dbPath      = "./tmp/"
	dbFile      = "./tmp/MANIFEST"
	genesisData = "First Transaction from Genesis"
)

type BlockChain struct {
	mainChain []*Block
}

var Blockchain BlockChain

type Block struct {
	Hash         []byte
	Transactions []*Transaction
	PrevHash     []byte
	Nonce        int
}

func (b *Block) HashTransactions() []byte {
	var txHashes [][]byte
	var txHash [32]byte

	for _, tx := range b.Transactions {
		txHashes = append(txHashes, tx.ID)
	}
	txHash = sha256.Sum256(bytes.Join(txHashes, []byte{}))

	return txHash[:]
}

// CreateBlock creates a new block using the list of Transactions and a prevHash
// it returns a pointer to a Block struct
//
// For the creation of a new block we need to run a proof of work algorithm
func CreateBlock(txs []*Transaction, prevHash []byte) *Block {
	block := &Block{[]byte{}, txs, prevHash, 0}
	pow := NewProof(block)
	nonce, hash := pow.RunPoWAlg()

	block.Hash = hash[:]
	block.Nonce = nonce

	return block
}

// For genesis we need a coinbase transaction because each block must have at least one transaction
func Genesis(coinbase *Transaction) *Block {
	return CreateBlock([]*Transaction{coinbase}, []byte{})
}

// Helper function to return a slice of bytes from a block input
func (block *Block) BlockToBytes() []byte {
	var bytesBlock bytes.Buffer
	encoder := gob.NewEncoder(&bytesBlock)
	err := encoder.Encode(block)
	Handle(err)

	return bytesBlock.Bytes()
}

// Helper function to return a pointer to a block struct from a slice of bytes
func BytesToBlock(data []byte) *Block {
	var block Block
	reader := bytes.NewReader(data)
	decoder := gob.NewDecoder(reader)
	err := decoder.Decode(&block)
	Handle(err)

	return &block
}

func Handle(err error) {
	if err != nil {
		log.Panic(err)
	}
}

func InitBlockChain() {
	wallets, _ := wallet.CreateWallets()
	address := wallets.AddWallet()
	wallets.SaveFile()
	cbtx := CoinbaseTx(address, genesisData)
	genesis := Genesis(cbtx)
	fmt.Printf("Genesis created\nFirst wallet addres is: %s\n", address)
	Blockchain.mainChain = append(Blockchain.mainChain, genesis)
}

// func ContinueBlockChain(address string) *BlockChain {
// 	var lastHash []byte

// 	err = db.Update(func(txn *badger.Txn) error {
// 		item, err := txn.Get([]byte("lh"))
// 		Handle(err)
// 		err = item.Value(func(val []byte) error {
// 			lastHash = val
// 			return nil
// 		})
// 		return err
// 	})
// 	Handle(err)

// 	chain := BlockChain{lastHash, db}

// 	return &chain
// }

func AddBlock(txs []*Transaction) {

	lastHash := Blockchain.mainChain[len(Blockchain.mainChain)-1].Hash

	newBlock := CreateBlock(txs, lastHash)

	Blockchain.mainChain = append(Blockchain.mainChain, newBlock)
}

func (blockchain BlockChain) printChain() {

	for _, block := range blockchain.mainChain {

		fmt.Printf("Hash: %x\n", block.Hash)
		fmt.Printf("Prev. hash: %x\n", block.PrevHash)
		pow := NewProof(block)
		fmt.Printf("PoW: %s\n", strconv.FormatBool(pow.ValidatePoW()))
		for _, tx := range block.Transactions {
			fmt.Println(tx.Inputs)
			fmt.Println(tx.Outputs)
		}
		fmt.Println()
	}
}

// given an address find the unsepnt transaction to see how much is available
func (blockchain *BlockChain) FindUnspentTransactions(pubKeyHash []byte) []Transaction {
	var unspentTxs []Transaction

	spentTXOs := make(map[string][]int)

	for _, block := range blockchain.mainChain {

		for _, tx := range block.Transactions {
			txID := hex.EncodeToString(tx.ID)

		Outputs:
			for outIdx, out := range tx.Outputs {
				if spentTXOs[txID] != nil {
					for _, spentOut := range spentTXOs[txID] {
						if spentOut == outIdx {
							continue Outputs
						}
					}
				}
				if out.IsLockedWithKey(pubKeyHash) {
					unspentTxs = append(unspentTxs, *tx)
				}
			}
			if tx.IsCoinbase() == false {
				for _, in := range tx.Inputs {
					if in.UsesKey(pubKeyHash) {
						inTxID := hex.EncodeToString(in.ID)
						spentTXOs[inTxID] = append(spentTXOs[inTxID], in.Out)
					}
				}
			}
		}
	}
	return unspentTxs
}

func (chain *BlockChain) FindUTXO(pubKeyHash []byte) []TxOutput {
	var UTXOs []TxOutput
	unspentTransactions := chain.FindUnspentTransactions(pubKeyHash)

	for _, tx := range unspentTransactions {
		for _, out := range tx.Outputs {
			if out.IsLockedWithKey(pubKeyHash) {
				UTXOs = append(UTXOs, out)
			}
		}
	}
	return UTXOs
}

// after finding unspent outputs we see how much can be spent
func (chain *BlockChain) FindSpendableOutputs(pubKeyHash []byte, amount int) (int, map[string][]int) {
	unspentOuts := make(map[string][]int)
	unspentTxs := chain.FindUnspentTransactions(pubKeyHash)
	accumulated := 0

Work:
	for _, tx := range unspentTxs {
		txID := hex.EncodeToString(tx.ID)

		for outIdx, out := range tx.Outputs {
			if out.IsLockedWithKey(pubKeyHash) && accumulated < amount {
				accumulated += out.Value
				unspentOuts[txID] = append(unspentOuts[txID], outIdx)

				if accumulated >= amount {
					break Work
				}
			}
		}
	}

	return accumulated, unspentOuts
}

func (blockchain *BlockChain) FindTransaction(ID []byte) (Transaction, error) {

	for _, block := range blockchain.mainChain {

		for _, tx := range block.Transactions {
			if bytes.Compare(tx.ID, ID) == 0 {
				return *tx, nil
			}
		}

		if len(block.PrevHash) == 0 {
			break
		}
	}

	return Transaction{}, errors.New("Transaction does not exist")
}

func (blockchain *BlockChain) SignTransaction(tx *Transaction, privKey ecdsa.PrivateKey) {
	prevTXs := make(map[string]Transaction)

	for _, in := range tx.Inputs {
		prevTX, err := blockchain.FindTransaction(in.ID)
		Handle(err)
		prevTXs[hex.EncodeToString(prevTX.ID)] = prevTX
	}
	tx.Sign(privKey, prevTXs)
}

func (blockchain *BlockChain) VerifyTransaction(tx *Transaction) bool {

	if tx.IsCoinbase() {
		return true
	}

	prevTXs := make(map[string]Transaction)

	for _, in := range tx.Inputs {
		prevTX, err := blockchain.FindTransaction(in.ID)
		Handle(err)
		prevTXs[hex.EncodeToString(prevTX.ID)] = prevTX
	}
	return tx.Verify(prevTXs)
}

func (blockchain *BlockChain) GetBalance(address string) {
	balance := 0
	if !wallet.ValidateAddress(address) {
		log.Panic("Address is not valid")
	}
	pubKeyHash := wallet.Base58Decode([]byte(address))
	pubKeyHash = pubKeyHash[1 : len(pubKeyHash)-4]
	UTXOs := blockchain.FindUTXO(pubKeyHash)

	for _, out := range UTXOs {
		balance += out.Value
	}
	fmt.Printf("Balance of %s: %d\n", address, balance)
}

var mutex = &sync.Mutex{}

func MakeBasicHost(listenPort int, secio bool, randseed int64) (host.Host, error) {

	// if the seed = 0 => real cryptographic randomness
	// otherwise deterministic randomness source to make generated keys stay the same across multiple runs
	var r io.Reader

	if randseed == 0 {
		r = rand.Reader
	} else {
		r = mrand.New(mrand.NewSource(randseed))
	}

	// generate key pair for this host
	priv, _, err := crypto.GenerateKeyPairWithReader(crypto.RSA, 2048, r)
	if err != nil {
		return nil, err
	}

	localAddr := GetIpAddr().String()
	localAddr = localAddr[:strings.IndexByte(localAddr, ':')]

	opts := []libp2p.Option{
		libp2p.ListenAddrStrings(fmt.Sprintf("/ip4/"+localAddr+"/tcp/%d", listenPort)),
		libp2p.Identity(priv),
	}

	basicHost, err := libp2p.New(context.Background(), opts...)
	if err != nil {
		return nil, err
	}

	hostAddr, _ := ma.NewMultiaddr(fmt.Sprintf("/ipfs/%s", basicHost.ID().Pretty()))

	addrs := basicHost.Addrs()
	var addr ma.Multiaddr

	for _, i := range addrs {
		if strings.HasPrefix(i.String(), "/ip4") {
			addr = i
			break
		}
	}

	fullAddr := addr.Encapsulate(hostAddr)
	log.Printf("I am %s\n", fullAddr)

	if secio {
		log.Printf("Now run \"go run main.go -l %d -d %s -secio\" on a different terminal\n", listenPort+1, fullAddr)
	} else {
		log.Printf("Now run \"go run main.go -l %d -d %s\" on a different terminal\n", listenPort+1, fullAddr)
	}

	return basicHost, nil
}

func HandleStream(s net1.Stream) {

	log.Printf("Got a new Stream")

	// buffer stream for non blocking read and write
	rw := bufio.NewReadWriter(bufio.NewReader(s), bufio.NewWriter(s))

	go ReadData(rw)
	go WriteData(rw)
}

func ReadData(rw *bufio.ReadWriter) {
	for {
		str, err := rw.ReadString('\n')
		if err != nil {
			log.Fatal(err)
		}

		if str == "" {
			return
		}

		if str != "\n" {
			chain := make([]*Block, 0)
			if err := json.Unmarshal([]byte(str), &chain); err != nil {
				log.Fatal(err)
			}

			mutex.Lock()
			if len(chain) > len(Blockchain.mainChain) {
				Blockchain.mainChain = chain
				bytes, err := json.MarshalIndent(Blockchain, "", "  ")
				if err != nil {

					log.Fatal(err)
				}
				// Green console color: 	\x1b[32m
				// Reset console color: 	\x1b[0m
				fmt.Printf("\x1b[32m%s\x1b[0m> ", string(bytes))
			}
			mutex.Unlock()
		}
	}
}

func WriteData(rw *bufio.ReadWriter) {
	go func() {
		for {
			time.Sleep(5 * time.Second)

			mutex.Lock()
			bytes, err := json.Marshal(Blockchain.mainChain)
			if err != nil {
				log.Println(err)
			}
			rw.WriteString(fmt.Sprintf("%s\n", string(bytes)))
			rw.Flush()
			mutex.Unlock()
		}
	}()

	stdReader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print("> ")
		sendData, err := stdReader.ReadString('\n')
		if err != nil {
			log.Fatal(err)
		}

		sendData = strings.Replace(sendData, "\n", "", -1)
		tokens := strings.Split(sendData, " ")
		// we don't check if the addresses are good
		if strings.Compare(tokens[0], "send") == 0 {
			amount, err := strconv.Atoi(tokens[1])
			if err != nil {
				continue
			}
			if !wallet.ValidateAddress(tokens[3]) {
				log.Panic("Address is not valid")
			}
			if !wallet.ValidateAddress(tokens[2]) {
				log.Panic("Address is not valid")
			}
			mutex.Lock()
			tx := NewTransaction(tokens[2], tokens[3], amount, &Blockchain)
			cbTx := CoinbaseTx(tokens[2], "")
			AddBlock([]*Transaction{cbTx, tx})
			mutex.Unlock()

			bytes, err := json.Marshal(Blockchain.mainChain)
			if err != nil {
				log.Println(err)
			}
			spew.Dump(Blockchain.mainChain)
			mutex.Lock()
			rw.WriteString(fmt.Sprintf("%s\n", string(bytes)))
			rw.Flush()
			mutex.Unlock()
		} else if strings.Compare(tokens[0], "get") == 0 && strings.Compare(tokens[1], "balance") == 0 {
			Blockchain.GetBalance(tokens[2])
		} else if strings.Compare(tokens[0], "create") == 0 {
			wallets, _ := wallet.CreateWallets()
			address := wallets.AddWallet()
			wallets.SaveFile()
			fmt.Printf("New address is: %s\n", address)
		}

		// NewTransaction()

		// bpm := sendData
		// newBlock := CreateBlock(bpm, Mainchain.Blocks[len(Mainchain.Blocks)-1].Hash)

		// mutex.Lock()
		// Mainchain.Blocks = append(Mainchain.Blocks, newBlock)
		// mutex.Unlock()

		// bytes, err := json.Marshal(Mainchain.Blocks)
		// if err != nil {
		// 	log.Println(err)
		// }

		// spew.Dump(Mainchain.Blocks)
	}
}

func GetIpAddr() *net.TCPAddr {
	conn, err := net.Dial("tcp", "8.8.8.8:443")
	if err != nil {
		fmt.Println(err)
		return nil
	}

	defer conn.Close()
	return conn.LocalAddr().(*net.TCPAddr)
}
