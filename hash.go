package main

import (
	"hash/fnv"
	"sort"
	"strconv"
)

// hashRingNode represents a virtual node on the consistent hash ring.
type hashRingNode struct {
	hash    uint64
	backend BackendConfig
}

// hashRing is a simple in-memory consistent hashing ring.
type hashRing struct {
	nodes []hashRingNode
}

// newHashRing builds a consistent hash ring with the given backends and replicas.
func newHashRing(backends []BackendConfig, replicas int) *hashRing {
	if len(backends) == 0 {
		return &hashRing{}
	}
	if replicas <= 0 {
		replicas = 64
	}

	nodes := make([]hashRingNode, 0, len(backends)*replicas)
	for _, b := range backends {
		for i := 0; i < replicas; i++ {
			h := fnv.New64a()
			h.Write([]byte(b.ID))
			h.Write([]byte{0})
			h.Write([]byte(strconv.Itoa(i)))
			nodes = append(nodes, hashRingNode{
				hash:    h.Sum64(),
				backend: b,
			})
		}
	}

	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].hash < nodes[j].hash
	})

	return &hashRing{nodes: nodes}
}

// choose returns the backend for the given protocol, domain suffix, and session ID (consistent hash).
func (r *hashRing) choose(protocol, domainSuffix string, sessionID []byte) BackendConfig {
	if len(r.nodes) == 0 {
		return BackendConfig{}
	}

	h := fnv.New64a()
	h.Write([]byte(protocol))
	h.Write([]byte{0})
	h.Write([]byte(domainSuffix))
	h.Write([]byte{0})
	h.Write(sessionID)
	keyHash := h.Sum64()

	idx := sort.Search(len(r.nodes), func(i int) bool {
		return r.nodes[i].hash >= keyHash
	})
	if idx == len(r.nodes) {
		idx = 0
	}
	return r.nodes[idx].backend
}

