// Copyright 2016 Christian Decker. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package seed

import (
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/lightningnetwork/lnd/lnrpc"
)

const (
	// defaultPort is the default port for lightning nodes. A and AAAA
	// queries only return nodes that listen to this port, SRV queries can
	// actually specify a port, so they return all nodes.
	defaultPort = 9735

	// dialTimeoutDurationis the default duration that we'll wait until we
	// determine that we can't reach an address from dialing.
	dialTimeoutDuration = time.Second * 5
)

var privateIPBlocks []*net.IPNet

// A bitfield in which bit 0 indicates whether it is an IPv6 if set,
// and bit 1 indicates whether it uses the default port if set.
type NodeType uint8

// Local model of a node,
type Node struct {
	Id string

	LastSeen time.Time

	Type NodeType

	Addresses []net.TCPAddr
}

// ChainView couples a network view for a particulr chain, and the node that
// will be populating that network view.
type ChainView struct {
	NetView *NetworkView

	Node lnrpc.LightningClient
}

// The local view of the network
type NetworkView struct {
	sync.Mutex

	chain string

	allNodes map[string]Node

	reachableNodes map[string]Node

	freshNodes chan Node
}

// NewNetworkView creates a new instance of a NetworkView.
func NewNetworkView(chain string) *NetworkView {
	n := &NetworkView{
		chain:          chain,
		allNodes:       make(map[string]Node),
		reachableNodes: make(map[string]Node),
		freshNodes:     make(chan Node, 100),
	}

	go n.reachabilityPruner()
	return n
}

func isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() {
		return true
	}

	for _, block := range privateIPBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// Return a random sample matching the NodeType, or just any node if
// query is set to `0xFF`. Relies on random map-iteration ordering
// internally.
func (nv *NetworkView) RandomSample(query NodeType, count int) []Node {
	nv.Lock()
	defer nv.Unlock()

	var result []Node
	for _, n := range nv.reachableNodes {
		if n.Type&query != 0 || query == 255 {
			result = append(result, n)
		}
		if len(result) == count {
			break
		}
	}

	// fmt.Println("Num reachable nodes: %v", len(nv.reachableNodes))
	log.Infof("Num reachable nodes: %v", len(nv.reachableNodes))

	return result
}

// Insert nodes into the map of known nodes. Existing nodes with the
// same Id are overwritten.
func (nv *NetworkView) AddNode(node *lnrpc.LightningNode) (*Node, error) {
	n := &Node{
		Id:       node.PubKey,
		LastSeen: time.Now(),
	}

	for _, netAddr := range node.Addresses {
		// If the address doesn't already have a port, we'll assume the
		// current default port.
		var addr string
		_, _, err := net.SplitHostPort(netAddr.Addr)
		if err != nil {
			addr = net.JoinHostPort(netAddr.Addr, strconv.Itoa(defaultPort))
		} else {
			addr = netAddr.Addr
		}

		parsedAddr, err := net.ResolveTCPAddr(netAddr.Network, addr)
		if err != nil {
			return nil, err
		}

		if parsedAddr.IP.To4() == nil {
			n.Type |= 1
		} else {
			n.Type |= 1 << 2
		}

		if parsedAddr.Port == defaultPort {
			n.Type |= 1 << 1
		}

		n.Addresses = append(n.Addresses, *parsedAddr)
	}

	if len(n.Addresses) == 0 {
		return nil, fmt.Errorf("node had no addresses")
	}

	nv.Lock()
	nv.allNodes[n.Id] = *n
	nv.Unlock()

	go func() {
		nv.freshNodes <- *n
	}()

	return n, nil
}

func copyNodeMap(a map[string]Node) map[string]Node {
	n := make(map[string]Node, len(a))
	for k, v := range a {
		n[k] = v
	}
	return n
}

// reachabilityPruner is a goroutine whose job it is to maintain the allnodes
// and reachableNodes map. Each time a new node is added, we'll attempt to see
// if we can actually connect to it. If so, then we'll add it to the
// reachableNodes. Every hour we'll examine the reachableNodes map to ensure
// that all posted nodes are still reachable, if not, we'll demote them.
func (nv *NetworkView) reachabilityPruner() {
	// We'll create a new ticker that'll go off every one hour which marks
	// the start of our reachability pruning.
	pruneTicker := time.NewTicker(time.Hour)

	// reachableAddrs is a helper function that determines if a node is
	// reachable or not. In order to determine reachability, we'll attempt
	// to make a connection on each of the addresses advertised by a node.
	// The set of reachable addresses for a node are returned.
	reachableAddrs := func(n Node) []net.TCPAddr {
		var addrs []net.TCPAddr

		for _, addr := range n.Addresses {
			// TODO(roasbeef): use brontide to ensure pubkey
			// identity

			log.Infof("Checking Node(%v) (%v) for reachability @ %v",
				n.Id, nv.chain, addr.String())

			tcpConn, err := net.DialTimeout(
				"tcp", addr.String(), dialTimeoutDuration,
			)
			if err != nil {
				log.Infof("Unable to reach %v via %v: %v", n.Id,
					addr, err)
				if tcpConn != nil {
					tcpConn.Close()
				}
				continue
			}
			tcpConn.Close()

			addrs = append(addrs, addr)
		}

		return addrs
	}

	seenNodes := make(map[string]struct{})

	// extractReachableAddrs attempts to move the target node to the
	// reachableNodes map iff, it has reachable addresses. Only the
	// addresses marked reachable are added.
	extractReachableAddrs := func(newNode Node, prune bool) {
		nv.Lock()
		if _, ok := seenNodes[newNode.Id]; ok {
			nv.Unlock()
			return
		}
		nv.Unlock()

		nv.Lock()
		seenNodes[newNode.Id] = struct{}{}
		nv.Unlock()

		validAddrs := reachableAddrs(newNode)
		if len(validAddrs) == 0 {
			log.Infof("Node(%v) (%v) has no reachable addresses, "+
				"prune=%v", newNode.Id, nv.chain, prune)

			// If prune is no, then if this node has no more
			// reachable addresses, we'll remove it from out set of
			// reachable nodes.
			if prune {
				nv.Lock()
				delete(nv.reachableNodes, newNode.Id)
				nv.Unlock()
			}

			return
		}

		newNode.Addresses = validAddrs

		nv.Lock()
		nv.reachableNodes[newNode.Id] = newNode
		log.Infof("Node(%v) (%v) is reachable number of reachable "+
			"nodes: %v", newNode.Id, nv.chain, len(nv.reachableNodes))
		nv.Unlock()
	}

	numFds := 100
	searchSema := make(chan struct{}, 100)
	for i := 0; i < numFds; i++ {
		searchSema <- struct{}{}
	}
	for {
		select {
		// A new node has just been discovered, if we haven't checked
		// this node recently, then we'll attempt to see which of its
		// addresses are reachable.
		case newNode := <-nv.freshNodes:
			go func() {
				// log.Infof("waiting to grab sema")
				<-searchSema

				defer func() {
					searchSema <- struct{}{}
					// log.Infof("sema returned")
				}()

				// log.Infof("got sema")
				extractReachableAddrs(newNode, false)
			}()

		// The prune timer has ticked, so we'll do two things: try to
		// move nodes from allNodes to reachableNodes, and also see if
		// there are any nodes marked reachable which no longer are.
		case <-pruneTicker.C:
			log.Infof("Pruning %v nodes for reachability", nv.chain)

			// First, we'll check to see if any of the nodes that
			// are within the allNodes, but not reachableNodes map
			// are now reachable.
			nv.Lock()
			allNodes := copyNodeMap(nv.allNodes)
			nv.Unlock()
			for _, node := range allNodes {
				// If it's already marked partially reachable,
				// then we'll skip over it.
				//
				// TODO(roasbeef): query other addrs
				nv.Lock()
				if _, ok := nv.reachableNodes[node.Id]; ok {
					nv.Unlock()
					continue
				}
				nv.Unlock()

				// Otherwise, we'll attempt to filter out it's
				// set of reachable addresses.
				extractReachableAddrs(node, false)
			}

			// Next, we'll possibly prune away any nodes which are
			// currently in the set of reachable nodes, but which
			// are no longer reachable.
			nv.Lock()
			reachableNodes := copyNodeMap(nv.reachableNodes)
			nv.Unlock()
			for _, node := range reachableNodes {
				extractReachableAddrs(node, true)
			}

			nv.Lock()
			log.Infof("Total number of reachable %v nodes: %v",
				nv.chain, len(nv.reachableNodes))
			seenNodes = make(map[string]struct{})
			nv.Unlock()
		}
	}
}

func init() {
	for _, cidr := range []string{
		"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"169.254.0.0/16", // RFC3927 link-local
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
		"fc00::/7",       // IPv6 unique local addr
	} {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Errorf("parse error on %q: %v", cidr, err))
		}
		privateIPBlocks = append(privateIPBlocks, block)
	}
}
