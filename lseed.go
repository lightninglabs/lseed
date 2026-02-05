package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	macaroon "gopkg.in/macaroon.v2"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/macaroons"
	"github.com/roasbeef/lseed/seed"
	log "github.com/sirupsen/logrus"
)

var (
	listenAddrUDP = flag.String("listenUDP", "0.0.0.0:53", "UDP listen address for incoming requests.")
	listenAddrTCP = flag.String("listenTCP", "0.0.0.0:53", "TCP listen address for incoming requests.")

	bitcoinNodeHost  = flag.String("btc-lnd-node", "", "The host:port of the backing btc lnd node")
	litecoinNodeHost = flag.String("ltc-lnd-node", "", "The host:port of the backing ltc lnd node")
	testNodeHost     = flag.String("test-lnd-node", "", "The host:port of the backing btc testlnd node")

	bitcoinTLSPath  = flag.String("btc-tls-path", "", "The path to the TLS cert for the btc lnd node")
	litecoinTLSPath = flag.String("ltc-tls-path", "", "The path to the TLS cert for the ltc lnd node")
	testTLSPath     = flag.String("test-tls-path", "", "The path to the TLS cert for the test lnd node")

	bitcoinMacPath  = flag.String("btc-mac-path", "", "The path to the macaroon for the btc lnd node")
	litecoinMacPath = flag.String("ltc-mac-path", "", "The path to the macaroon for the ltc lnd node")
	testMacPath     = flag.String("test-mac-path", "", "The path to the macaroon for the test lnd node")

	signetNodeHost = flag.String("signet-lnd-node", "", "The host:port of the backing btc signet lnd node")
	signetTLSPath  = flag.String("signet-tls-path", "", "The path to the TLS cert for the signet lnd node")
	signetMacPath  = flag.String("signet-mac-path", "", "The path to the macaroon for the signet lnd node")

	testnet4NodeHost = flag.String("testnet4-lnd-node", "", "The host:port of the btc testnet4 lnd node")
	testnet4TLSPath  = flag.String("testnet4-tls-path", "", "The path to the TLS cert for the testnet4 lnd node")
	testnet4MacPath  = flag.String("testnet4-mac-path", "", "The path to the macaroon for the testnet4 lnd node")

	rootDomain = flag.String("root-domain", "nodes.lightning.directory", "Root DNS seed domain.")

	authoritativeIP = flag.String("root-ip", "127.0.0.1", "The IP address of the authoritative name server. This is used to create a dummy record which allows clients to access the seed directly over TCP")

	pollInterval = flag.Int("poll-interval", 600, "Time between polls to lightningd for updates")

	debug = flag.Bool("debug", false, "Be very verbose")

	numResults = flag.Int("results", 25, "How many results shall we return to a query?")
)

var (
	lndHomeDir = btcutil.AppDataDir("lnd", false)

	maxMsgRecvSize = grpc.MaxCallRecvMsgSize(1 * 1024 * 1024 * 50)
)

// cleanAndExpandPath expands environment variables and leading ~ in the passed
// path, cleans the result, and returns it.
// This function is taken from https://github.com/btcsuite/btcd
func cleanAndExpandPath(path string) string {
	// Expand initial ~ to OS specific home directory.
	if strings.HasPrefix(path, "~") {
		homeDir := filepath.Dir(lndHomeDir)
		path = strings.Replace(path, "~", homeDir, 1)
	}

	// NOTE: The os.ExpandEnv doesn't work with Windows-style %VARIABLE%,
	// but the variables can still be expanded via POSIX-style $VARIABLE.
	return filepath.Clean(os.ExpandEnv(path))
}

// initLightningClient attempts to initialize, and connect out to the backing
// lnd node as specified by the lndNode ccommand line flag.
func initLightningClient(nodeHost, tlsCertPath, macPath string) (lnrpc.LightningClient, error) {

	// First attempt to establish a connection to lnd's RPC sever.
	tlsCertPath = cleanAndExpandPath(tlsCertPath)
	creds, err := credentials.NewClientTLSFromFile(tlsCertPath, "")
	if err != nil {
		return nil, fmt.Errorf("unable to read cert file: %v", err)
	}
	opts := []grpc.DialOption{grpc.WithTransportCredentials(creds)}

	// Load the specified macaroon file.
	macPath = cleanAndExpandPath(macPath)
	macBytes, err := ioutil.ReadFile(macPath)
	if err != nil {
		return nil, err
	}
	mac := &macaroon.Macaroon{}
	if err = mac.UnmarshalBinary(macBytes); err != nil {
		return nil, err
	}

	// Now we append the macaroon credentials to the dial options.
	cred, err := macaroons.NewMacaroonCredential(mac)
	if err != nil {
		return nil, fmt.Errorf("unable to create macaroon credential: "+
			"%v", err)
	}
	opts = append(opts, grpc.WithPerRPCCredentials(cred))
	opts = append(opts, grpc.WithDefaultCallOptions(maxMsgRecvSize))

	conn, err := grpc.Dial(nodeHost, opts...)
	if err != nil {
		return nil, fmt.Errorf("unable to dial to lnd's gRPC server: %v",
			err)
	}

	// If we're able to connect out to the lnd node, then we can start up
	// our RPC connection properly.
	lnd := lnrpc.NewLightningClient(conn)

	// Before we proceed, make sure that we can query the target node.
	_, err = lnd.GetInfo(
		context.Background(), &lnrpc.GetInfoRequest{},
	)
	if err != nil {
		return nil, err
	}

	return lnd, nil
}

// poller regularly polls the backing lnd node and updates the local network
// view.
func poller(lnd lnrpc.LightningClient, nview *seed.NetworkView) {
	scrapeGraph := func() {
		graphReq := &lnrpc.ChannelGraphRequest{}
		graph, err := lnd.DescribeGraph(
			context.Background(), graphReq,
		)
		if err != nil {
			return
		}

		log.Debugf("Got %d nodes from lnd", len(graph.Nodes))
		for _, node := range graph.Nodes {
			if len(node.Addresses) == 0 {
				continue
			}

			if _, err := nview.AddNode(node); err != nil {
				log.Debugf("Unable to add node: %v", err)
			} else {
				log.Debugf("Adding node: %v", node.Addresses)
			}
		}
	}

	scrapeGraph()

	ticker := time.NewTicker(time.Second * time.Duration(*pollInterval))
	for range ticker.C {
		scrapeGraph()
	}
}

// Parse flags and configure subsystems according to flags
func configure() {
	flag.Parse()
	if *debug {
		log.SetLevel(log.DebugLevel)
		log.Infof("Logging on level Debug")
	} else {
		log.SetLevel(log.InfoLevel)
		log.Infof("Logging on level Info")
	}
}

// Main entry point for the lightning-seed
func main() {
	log.SetOutput(os.Stdout)

	configure()

	go func() {
		log.Println(http.ListenAndServe(":9091", nil))
	}()

	netViewMap := make(map[string]*seed.ChainView)

	if *bitcoinNodeHost != "" && *bitcoinTLSPath != "" && *bitcoinMacPath != "" {
		log.Infof("Creating BTC chain view")

		lndNode, err := initLightningClient(
			*bitcoinNodeHost, *bitcoinTLSPath, *bitcoinMacPath,
		)
		if err != nil {
			panic(fmt.Sprintf("unable to connect to btc lnd: %v", err))
		}

		nView := seed.NewNetworkView("bitcoin")
		go poller(lndNode, nView)

		log.Infof("BTC chain view active")

		netViewMap[""] = &seed.ChainView{
			NetView: nView,
			Node:    lndNode,
		}

	}

	if *litecoinNodeHost != "" && *litecoinTLSPath != "" && *litecoinMacPath != "" {
		log.Infof("Creating LTC chain view")

		lndNode, err := initLightningClient(
			*litecoinNodeHost, *litecoinTLSPath, *litecoinMacPath,
		)
		if err != nil {
			panic(fmt.Sprintf("unable to connect to ltc lnd: %v", err))
		}

		nView := seed.NewNetworkView("litecoin")
		go poller(lndNode, nView)

		netViewMap["ltc."] = &seed.ChainView{
			NetView: nView,
			Node:    lndNode,
		}

	}
	if *testNodeHost != "" && *testTLSPath != "" && *testMacPath != "" {
		log.Infof("Creating BTC testnet chain view")

		lndNode, err := initLightningClient(
			*testNodeHost, *testTLSPath, *testMacPath,
		)
		if err != nil {
			panic(fmt.Sprintf("unable to connect to test lnd: %v", err))
		}

		nView := seed.NewNetworkView("testnet")
		go poller(lndNode, nView)

		log.Infof("TBCT chain view active")

		netViewMap["test."] = &seed.ChainView{
			NetView: nView,
			Node:    lndNode,
		}
	}

	if *signetNodeHost != "" && *signetTLSPath != "" && *signetMacPath != "" {
		log.Infof("Creating BTC signet chain view")

		lndNode, err := initLightningClient(
			*signetNodeHost, *signetTLSPath, *signetMacPath,
		)
		if err != nil {
			panic(fmt.Sprintf("unable to connect to signet lnd: %v", err))
		}

		nView := seed.NewNetworkView("signet")
		go poller(lndNode, nView)

		log.Infof("Signet chain view active")

		netViewMap["signet."] = &seed.ChainView{
			NetView: nView,
			Node:    lndNode,
		}
	}

	if *testnet4NodeHost != "" && *testnet4TLSPath != "" && *testnet4MacPath != "" {
		log.Infof("Creating BTC testnet4 chain view")

		lndNode, err := initLightningClient(
			*testnet4NodeHost, *testnet4TLSPath, *testnet4MacPath,
		)
		if err != nil {
			panic(fmt.Sprintf("unable to connect to testnet4 lnd: %v", err))
		}

		nView := seed.NewNetworkView("testnet4")
		go poller(lndNode, nView)

		log.Infof("Testnet4 chain view active")

		netViewMap["test4."] = &seed.ChainView{
			NetView: nView,
			Node:    lndNode,
		}
	}

	if len(netViewMap) == 0 {
		panic(fmt.Sprintf("must specify at least one node type"))
	}

	rootIP := net.ParseIP(*authoritativeIP)
	dnsServer := seed.NewDnsServer(
		netViewMap, *listenAddrUDP, *listenAddrTCP, *rootDomain, rootIP,
	)

	dnsServer.Serve()
}
