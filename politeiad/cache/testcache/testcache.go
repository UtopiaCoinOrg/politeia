// Copyright (c) 2017-2019 The UtopiaCoinOrg developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package testcache

import (
	"fmt"
	"strconv"
	"sync"

	UtopiaCoinOrg "github.com/UtopiaCoinOrg/politeia/ucplugin"
	"github.com/UtopiaCoinOrg/politeia/politeiad/cache"
)

// testcache provides a implementation of the cache interface that stores
// records in memory and that can be used for testing.
type testcache struct {
	sync.RWMutex
	records map[string]map[string]cache.Record // [token][version]Record

	// UtopiaCoinOrg plugin
	comments         map[string][]UtopiaCoinOrg.Comment                // [token][]Comment
	authorizeVotes   map[string]map[string]UtopiaCoinOrg.AuthorizeVote // [token][version]AuthorizeVote
	startVotes       map[string]UtopiaCoinOrg.StartVote                // [token]StartVote
	startVoteReplies map[string]UtopiaCoinOrg.StartVoteReply           // [token]StartVoteReply
}

// NewRecords adds a record to the cache.
func (c *testcache) NewRecord(r cache.Record) error {
	c.Lock()
	defer c.Unlock()

	token := r.CensorshipRecord.Token
	_, ok := c.records[token]
	if !ok {
		c.records[token] = make(map[string]cache.Record)
	}

	c.records[token][r.Version] = r
	return nil
}

// record returns the most recent version of a record from the memory cache.
//
// This function must be called with the lock held.
func (c *testcache) record(token string) (*cache.Record, error) {
	records, ok := c.records[token]
	if !ok {
		return nil, cache.ErrRecordNotFound
	}

	var latest int
	for version := range records {
		v, err := strconv.Atoi(version)
		if err != nil {
			return nil, fmt.Errorf("parse version '%v' failed: %v",
				version, err)
		}

		if v > latest {
			latest = v
		}
	}

	// Sanity check
	if latest == 0 {
		return nil, cache.ErrRecordNotFound
	}

	r := records[strconv.Itoa(latest)]
	return &r, nil
}

// Record returns the most recent version of the record.
func (c *testcache) Record(token string) (*cache.Record, error) {
	c.RLock()
	defer c.RUnlock()

	return c.record(token)
}

// Records returns the most recent version of a set of records.
func (c *testcache) Records(tokens []string, fetchFiles bool) ([]cache.Record, error) {
	c.RLock()
	defer c.RUnlock()

	records := make([]cache.Record, 0, len(tokens))

	for _, token := range tokens {
		r, err := c.record(token)
		if err != nil {
			return nil, err
		}
		records = append(records, *r)
	}

	return records, nil
}

// recordVersion retreives a specific version of a record from the memory
// cache.
//
// This function must be called with the lock held.
func (c *testcache) recordVersion(token, version string) (*cache.Record, error) {
	_, ok := c.records[token]
	if !ok {
		return nil, cache.ErrRecordNotFound
	}

	r, ok := c.records[token][version]
	if !ok {
		return nil, cache.ErrRecordNotFound
	}

	return &r, nil
}

// RecordVersion returns a specific version of a record.
func (c *testcache) RecordVersion(token, version string) (*cache.Record, error) {
	c.RLock()
	defer c.RUnlock()

	return c.recordVersion(token, version)
}

// UpdateRecord is a stub to satisfy the cache interface.
func (c *testcache) UpdateRecord(r cache.Record) error {
	return nil
}

// UpdateRecordStatus updates the status of a record.
func (c *testcache) UpdateRecordStatus(token, version string, status cache.RecordStatusT, timestamp int64, metadata []cache.MetadataStream) error {
	c.Lock()
	defer c.Unlock()

	// Lookup record
	r, err := c.recordVersion(token, version)
	if err != nil {
		return err
	}

	// Update record
	r.Status = status
	r.Timestamp = timestamp
	r.Metadata = metadata
	c.records[token][version] = *r

	return nil
}

// UpdateRecordMetadata is a stub to satisfy the cache interface.
func (c *testcache) UpdateRecordMetadata(token string, md []cache.MetadataStream) error {
	return nil
}

// Inventory is a stub to satisfy the cache interface.
func (c *testcache) Inventory() ([]cache.Record, error) {
	return make([]cache.Record, 0), nil
}

// InventoryStats is a stub to satisfy the cache interface.
func (c *testcache) InventoryStats() (*cache.InventoryStats, error) {
	return &cache.InventoryStats{}, nil
}

// Setup is a stub to satisfy the cache interface.
func (c *testcache) Setup() error {
	return nil
}

// Build is a stub to satisfy the cache interface.
func (c *testcache) Build(records []cache.Record) error {
	return nil
}

func (c *testcache) RegisterPlugin(p cache.Plugin) error {
	return nil
}

// PluginSetup is a stub to satisfy the cache interface.
func (c *testcache) PluginSetup(id string) error {
	return nil
}

// PluginBuild is a stub to satisfy the cache interface.
func (c *testcache) PluginBuild(id, payload string) error {
	return nil
}

// PluginExec is a stub to satisfy the cache interface.
func (c *testcache) PluginExec(pc cache.PluginCommand) (*cache.PluginCommandReply, error) {
	var payload string
	var err error
	switch pc.ID {
	case UtopiaCoinOrg.ID:
		payload, err = c.utopiaExec(pc.Command,
			pc.CommandPayload, pc.ReplyPayload)
		if err != nil {
			return nil, err
		}
	}
	return &cache.PluginCommandReply{
		ID:      pc.ID,
		Command: pc.Command,
		Payload: payload,
	}, nil
}

// Close is a stub to satisfy the cache interface.
func (c *testcache) Close() {}

// New returns a new testcache context.
func New() *testcache {
	return &testcache{
		records:          make(map[string]map[string]cache.Record),
		comments:         make(map[string][]UtopiaCoinOrg.Comment),
		authorizeVotes:   make(map[string]map[string]UtopiaCoinOrg.AuthorizeVote),
		startVotes:       make(map[string]UtopiaCoinOrg.StartVote),
		startVoteReplies: make(map[string]UtopiaCoinOrg.StartVoteReply),
	}
}
