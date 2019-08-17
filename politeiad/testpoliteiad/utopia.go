// Copyright (c) 2017-2019 The UtopiaCoinOrg developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package testpoliteiad

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	UtopiaCoinOrg "github.com/UtopiaCoinOrg/politeia/ucplugin"
	v1 "github.com/UtopiaCoinOrg/politeia/politeiad/api/v1"
)

const (
	bestBlock uint32 = 1000
)

func (p *TestPoliteiad) authorizeVote(payload string) (string, error) {
	av, err := UtopiaCoinOrg.DecodeAuthorizeVote([]byte(payload))
	if err != nil {
		return "", err
	}

	// Sign authorize vote
	s := p.identity.SignMessage([]byte(av.Signature))
	av.Receipt = hex.EncodeToString(s[:])
	av.Timestamp = time.Now().Unix()
	av.Version = UtopiaCoinOrg.VersionAuthorizeVote

	p.Lock()
	defer p.Unlock()

	// Store authorize vote
	_, ok := p.authorizeVotes[av.Token]
	if !ok {
		p.authorizeVotes[av.Token] = make(map[string]UtopiaCoinOrg.AuthorizeVote)
	}

	r, err := p.record(av.Token)
	if err != nil {
		return "", err
	}

	p.authorizeVotes[av.Token][r.Version] = *av

	// Prepare reply
	avrb, err := UtopiaCoinOrg.EncodeAuthorizeVoteReply(
		UtopiaCoinOrg.AuthorizeVoteReply{
			Action:        av.Action,
			RecordVersion: r.Version,
			Receipt:       av.Receipt,
			Timestamp:     av.Timestamp,
		})
	if err != nil {
		return "", err
	}

	return string(avrb), nil
}

func (p *TestPoliteiad) startVote(payload string) (string, error) {
	sv, err := UtopiaCoinOrg.DecodeStartVote([]byte(payload))
	if err != nil {
		return "", err
	}

	p.Lock()
	defer p.Unlock()

	// Store start vote
	p.startVotes[sv.Vote.Token] = *sv

	// Prepare reply
	endHeight := bestBlock + sv.Vote.Duration
	svr := UtopiaCoinOrg.StartVoteReply{
		Version:          UtopiaCoinOrg.VersionStartVoteReply,
		StartBlockHeight: strconv.FormatUint(uint64(bestBlock), 10),
		EndHeight:        strconv.FormatUint(uint64(endHeight), 10),
		EligibleTickets:  []string{},
	}
	svrb, err := UtopiaCoinOrg.EncodeStartVoteReply(svr)
	if err != nil {
		return "", err
	}

	// Store reply
	p.startVoteReplies[sv.Vote.Token] = svr

	return string(svrb), nil
}

// utopiaExec executes the passed in plugin command.
func (p *TestPoliteiad) utopiaExec(pc v1.PluginCommand) (string, error) {
	switch pc.Command {
	case UtopiaCoinOrg.CmdStartVote:
		return p.startVote(pc.Payload)
	case UtopiaCoinOrg.CmdAuthorizeVote:
		return p.authorizeVote(pc.Payload)
	}
	return "", fmt.Errorf("invalid plugin command")
}
