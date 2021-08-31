package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"

	peer "github.com/libp2p/go-libp2p-peer"
	pstore "github.com/libp2p/go-libp2p-peerstore"
	"github.com/libp2p/go-libp2p/examples/p2p/blockchain"
	ma "github.com/multiformats/go-multiaddr"
)

func main() {

	listenF := flag.Int("l", 0, "wait for incoming connections")
	target := flag.String("d", "", "targer peer to dial")
	secio := flag.Bool("secio", false, "enable secio")
	seed := flag.Int64("seed", 0, "set random seed for id generation")
	flag.Parse()

	if *listenF == 0 {
		log.Fatal("Please provide a port to bing on with -l")
	}

	ha, err := blockchain.MakeBasicHost(*listenF, *secio, *seed)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(ha)

	if *target == "" {
		blockchain.InitBlockChain()
		log.Println("listening for connections")
		ha.SetStreamHandler("/p2p/1.0.0", blockchain.HandleStream)
		select {}
	} else {
		ha.SetStreamHandler("/p2p/1.0.0", blockchain.HandleStream)
		fmt.Println(target)
		ipfsaddr, err := ma.NewMultiaddr(*target)
		if err != nil {
			log.Fatalln(err)
		}

		pid, err := ipfsaddr.ValueForProtocol(ma.P_IPFS)
		if err != nil {
			log.Fatalln(err)
		}

		peerid, err := peer.IDB58Decode(pid)
		if err != nil {
			log.Fatalln(err)
		}

		targetPeerAddr, _ := ma.NewMultiaddr(
			fmt.Sprintf("/ipfs/%s", peer.IDB58Encode(peerid)))
		targetAddr := ipfsaddr.Decapsulate(targetPeerAddr)

		ha.Peerstore().AddAddr(peerid, targetAddr, pstore.PermanentAddrTTL)
		log.Println("opening stream")

		s, err := ha.NewStream(context.Background(), peerid, "/p2p/1.0.0")
		if err != nil {
			log.Fatalln(err)
		}

		rw := bufio.NewReadWriter(bufio.NewReader(s), bufio.NewWriter(s))

		go blockchain.WriteData(rw)
		go blockchain.ReadData(rw)

		select {}
	}
}
