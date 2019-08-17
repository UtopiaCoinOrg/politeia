// Copyright (c) 2017-2019 The UtopiaCoinOrg developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package testcache

import (
	UtopiaCoinOrg "github.com/UtopiaCoinOrg/politeia/ucplugin"
	"github.com/UtopiaCoinOrg/politeia/politeiad/cache"
)

func (c *testcache) getComments(payload string) (string, error) {
	gc, err := UtopiaCoinOrg.DecodeGetComments([]byte(payload))
	if err != nil {
		return "", err
	}

	c.RLock()
	defer c.RUnlock()

	gcrb, err := UtopiaCoinOrg.EncodeGetCommentsReply(
		UtopiaCoinOrg.GetCommentsReply{
			Comments: c.comments[gc.Token],
		})
	if err != nil {
		return "", err
	}

	return string(gcrb), nil
}

func (c *testcache) authorizeVote(cmdPayload, replyPayload string) (string, error) {
	av, err := UtopiaCoinOrg.DecodeAuthorizeVote([]byte(cmdPayload))
	if err != nil {
		return "", err
	}

	avr, err := UtopiaCoinOrg.DecodeAuthorizeVoteReply([]byte(replyPayload))
	if err != nil {
		return "", err
	}

	av.Receipt = avr.Receipt
	av.Timestamp = avr.Timestamp

	c.Lock()
	defer c.Unlock()

	_, ok := c.authorizeVotes[av.Token]
	if !ok {
		c.authorizeVotes[av.Token] = make(map[string]UtopiaCoinOrg.AuthorizeVote)
	}

	c.authorizeVotes[av.Token][avr.RecordVersion] = *av

	return replyPayload, nil
}

func (c *testcache) startVote(cmdPayload, replyPayload string) (string, error) {
	sv, err := UtopiaCoinOrg.DecodeStartVote([]byte(cmdPayload))
	if err != nil {
		return "", err
	}

	svr, err := UtopiaCoinOrg.DecodeStartVoteReply([]byte(replyPayload))
	if err != nil {
		return "", err
	}

	c.Lock()
	defer c.Unlock()

	// Store start vote data
	c.startVotes[sv.Vote.Token] = *sv
	c.startVoteReplies[sv.Vote.Token] = *svr

	return replyPayload, nil
}

func (c *testcache) voteDetails(payload string) (string, error) {
	vd, err := UtopiaCoinOrg.DecodeVoteDetails([]byte(payload))
	if err != nil {
		return "", err
	}

	c.Lock()
	defer c.Unlock()

	// Lookup the latest record version
	r, err := c.record(vd.Token)
	if err != nil {
		return "", err
	}

	// Prepare reply
	_, ok := c.authorizeVotes[vd.Token]
	if !ok {
		c.authorizeVotes[vd.Token] = make(map[string]UtopiaCoinOrg.AuthorizeVote)
	}

	vdb, err := UtopiaCoinOrg.EncodeVoteDetailsReply(
		UtopiaCoinOrg.VoteDetailsReply{
			AuthorizeVote:  c.authorizeVotes[vd.Token][r.Version],
			StartVote:      c.startVotes[vd.Token],
			StartVoteReply: c.startVoteReplies[vd.Token],
		})
	if err != nil {
		return "", err
	}

	return string(vdb), nil
}

func (c *testcache) utopiaExec(cmd, cmdPayload, replyPayload string) (string, error) {
	switch cmd {
	case UtopiaCoinOrg.CmdGetComments:
		return c.getComments(cmdPayload)
	case UtopiaCoinOrg.CmdAuthorizeVote:
		return c.authorizeVote(cmdPayload, replyPayload)
	case UtopiaCoinOrg.CmdStartVote:
		return c.startVote(cmdPayload, replyPayload)
	case UtopiaCoinOrg.CmdVoteDetails:
		return c.voteDetails(cmdPayload)
	}

	return "", cache.ErrInvalidPluginCmd
}
