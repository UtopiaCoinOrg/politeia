// Copyright (c) 2017-2019 The UtopiaCoinOrg developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/davecgh/go-spew/spew"
	"github.com/UtopiaCoinOrg/politeia/ucplugin"
	pd "github.com/UtopiaCoinOrg/politeia/politeiad/api/v1"
	"github.com/UtopiaCoinOrg/politeia/politeiad/cache"
	"github.com/UtopiaCoinOrg/politeia/util"
)

// utopiaGetComment sends the UtopiaCoinOrg plugin getcomment command to the cache and
// returns the specified comment.
func (p *politeiawww) utopiaGetComment(gc ucplugin.GetComment) (*ucplugin.Comment, error) {
	// Setup plugin command
	payload, err := ucplugin.EncodeGetComment(gc)
	if err != nil {
		return nil, err
	}

	pc := cache.PluginCommand{
		ID:             ucplugin.ID,
		Command:        ucplugin.CmdGetComment,
		CommandPayload: string(payload),
	}

	// Get comment from the cache
	reply, err := p.cache.PluginExec(pc)
	if err != nil {
		return nil, err
	}

	gcr, err := ucplugin.DecodeGetCommentReply([]byte(reply.Payload))
	if err != nil {
		return nil, err
	}

	return &gcr.Comment, nil
}

// utopiaCommentGetByID retrieves the specified UtopiaCoinOrg plugin comment from the
// cache.
func (p *politeiawww) utopiaCommentGetByID(token, commentID string) (*ucplugin.Comment, error) {
	gc := ucplugin.GetComment{
		Token:     token,
		CommentID: commentID,
	}
	return p.utopiaGetComment(gc)
}

// utopiaCommentGetBySignature retrieves the specified UtopiaCoinOrg plugin comment
// from the cache.
func (p *politeiawww) utopiaCommentGetBySignature(token, sig string) (*ucplugin.Comment, error) {
	gc := ucplugin.GetComment{
		Token:     token,
		Signature: sig,
	}
	return p.utopiaGetComment(gc)
}

// utopiaGetComments sends the UtopiaCoinOrg plugin getcomments command to the cache
// and returns all of the comments for the passed in proposal token.
func (p *politeiawww) utopiaGetComments(token string) ([]ucplugin.Comment, error) {
	// Setup plugin command
	gc := ucplugin.GetComments{
		Token: token,
	}

	payload, err := ucplugin.EncodeGetComments(gc)
	if err != nil {
		return nil, err
	}

	pc := cache.PluginCommand{
		ID:             ucplugin.ID,
		Command:        ucplugin.CmdGetComments,
		CommandPayload: string(payload),
	}

	// Get comments from the cache
	reply, err := p.cache.PluginExec(pc)
	if err != nil {
		return nil, fmt.Errorf("PluginExec: %v", err)
	}

	gcr, err := ucplugin.DecodeGetCommentsReply([]byte(reply.Payload))
	if err != nil {
		return nil, err
	}

	return gcr.Comments, nil
}

// utopiaGetBatchComments sends the UtopiaCoinOrg plugin GetBachComments command to the
// cache and returns all of the comments for each of the tokens passed in.
func (p *politeiawww) utopiaGetNumComments(tokens []string) (map[string]int, error) {

	// Setup plugin command
	gnc := ucplugin.GetNumComments{
		Tokens: tokens,
	}

	payload, err := ucplugin.EncodeGetNumComments(gnc)
	if err != nil {
		return nil, err
	}

	pc := cache.PluginCommand{
		ID:             ucplugin.ID,
		Command:        ucplugin.CmdGetNumComments,
		CommandPayload: string(payload),
	}

	// Get comments from the cache
	reply, err := p.cache.PluginExec(pc)
	if err != nil {
		return nil, fmt.Errorf("PluginExec: %v", err)
	}

	gncr, err := ucplugin.DecodeGetNumCommentsReply(
		[]byte(reply.Payload))
	if err != nil {
		return nil, err
	}

	return gncr.CommentsMap, nil
}

// utopiaCommentLikes sends the UtopiaCoinOrg plugin commentlikes command to the cache
// and returns all of the comment likes for the passed in comment.
func (p *politeiawww) utopiaCommentLikes(token, commentID string) ([]ucplugin.LikeComment, error) {
	// Setup plugin command
	cl := ucplugin.CommentLikes{
		Token:     token,
		CommentID: commentID,
	}

	payload, err := ucplugin.EncodeCommentLikes(cl)
	if err != nil {
		return nil, err
	}

	pc := cache.PluginCommand{
		ID:             ucplugin.ID,
		Command:        ucplugin.CmdCommentLikes,
		CommandPayload: string(payload),
	}

	// Get comment likes from cache
	reply, err := p.cache.PluginExec(pc)
	if err != nil {
		return nil, err
	}

	clr, err := ucplugin.DecodeCommentLikesReply([]byte(reply.Payload))
	if err != nil {
		return nil, err
	}

	return clr.CommentLikes, nil
}

// utopiaPropCommentLikes sends the UtopiaCoinOrg plugin proposalcommentslikes command
// to the cache and returns all of the comment likes for the passed in proposal
// token.
func (p *politeiawww) utopiaPropCommentLikes(token string) ([]ucplugin.LikeComment, error) {
	// Setup plugin command
	pcl := ucplugin.GetProposalCommentsLikes{
		Token: token,
	}

	payload, err := ucplugin.EncodeGetProposalCommentsLikes(pcl)
	if err != nil {
		return nil, err
	}

	pc := cache.PluginCommand{
		ID:             ucplugin.ID,
		Command:        ucplugin.CmdProposalCommentsLikes,
		CommandPayload: string(payload),
	}

	// Get proposal comment likes from cache
	reply, err := p.cache.PluginExec(pc)
	if err != nil {
		return nil, err
	}

	rp := []byte(reply.Payload)
	pclr, err := ucplugin.DecodeGetProposalCommentsLikesReply(rp)
	if err != nil {
		return nil, err
	}

	return pclr.CommentsLikes, nil
}

// utopiaVoteDetails sends the UtopiaCoinOrg plugin votedetails command to the cache
// and returns the vote details for the passed in proposal.
func (p *politeiawww) utopiaVoteDetails(token string) (*ucplugin.VoteDetailsReply, error) {
	// Setup plugin command
	vd := ucplugin.VoteDetails{
		Token: token,
	}

	payload, err := ucplugin.EncodeVoteDetails(vd)
	if err != nil {
		return nil, err
	}

	pc := cache.PluginCommand{
		ID:             ucplugin.ID,
		Command:        ucplugin.CmdVoteDetails,
		CommandPayload: string(payload),
	}

	// Get vote details from cache
	reply, err := p.cache.PluginExec(pc)
	if err != nil {
		return nil, err
	}

	vdr, err := ucplugin.DecodeVoteDetailsReply([]byte(reply.Payload))
	if err != nil {
		return nil, err
	}

	return vdr, nil
}

// utopiaProposalVotes sends the UtopiaCoinOrg plugin proposalvotes command to the
// cache and returns the vote results for the passed in proposal.
func (p *politeiawww) utopiaProposalVotes(token string) (*ucplugin.VoteResultsReply, error) {
	// Setup plugin command
	vr := ucplugin.VoteResults{
		Token: token,
	}

	payload, err := ucplugin.EncodeVoteResults(vr)
	if err != nil {
		return nil, err
	}

	pc := cache.PluginCommand{
		ID:             ucplugin.ID,
		Command:        ucplugin.CmdProposalVotes,
		CommandPayload: string(payload),
	}

	// Get proposal votes from cache
	reply, err := p.cache.PluginExec(pc)
	if err != nil {
		return nil, err
	}

	vrr, err := ucplugin.DecodeVoteResultsReply([]byte(reply.Payload))
	if err != nil {
		return nil, err
	}

	return vrr, nil
}

// utopiaInventory sends the UtopiaCoinOrg plugin inventory command to the cache and
// returns the UtopiaCoinOrg plugin inventory.
func (p *politeiawww) utopiaInventory() (*ucplugin.InventoryReply, error) {
	// Setup plugin command
	i := ucplugin.Inventory{}
	payload, err := ucplugin.EncodeInventory(i)
	if err != nil {
		return nil, err
	}

	pc := cache.PluginCommand{
		ID:             ucplugin.ID,
		Command:        ucplugin.CmdInventory,
		CommandPayload: string(payload),
	}

	// Get cache inventory
	reply, err := p.cache.PluginExec(pc)
	if err != nil {
		return nil, err
	}

	ir, err := ucplugin.DecodeInventoryReply([]byte(reply.Payload))
	if err != nil {
		return nil, err
	}

	return ir, nil
}

// utopiaTokenInventory sends the UtopiaCoinOrg plugin tokeninventory command to the
// cache.
func (p *politeiawww) utopiaTokenInventory(bestBlock uint64, includeUnvetted bool) (*ucplugin.TokenInventoryReply, error) {
	payload, err := ucplugin.EncodeTokenInventory(
		ucplugin.TokenInventory{
			BestBlock: bestBlock,
			Unvetted:  includeUnvetted,
		})
	if err != nil {
		return nil, err
	}

	pc := cache.PluginCommand{
		ID:             ucplugin.ID,
		Command:        ucplugin.CmdTokenInventory,
		CommandPayload: string(payload),
	}

	reply, err := p.cache.PluginExec(pc)
	if err != nil {
		return nil, err
	}

	tir, err := ucplugin.DecodeTokenInventoryReply([]byte(reply.Payload))
	if err != nil {
		return nil, err
	}

	return tir, nil
}

// utopiaLoadVoteResults sends the loadvotesummaries command to politeiad.
func (p *politeiawww) utopiaLoadVoteResults(bestBlock uint64) (*ucplugin.LoadVoteResultsReply, error) {
	// Setup plugin command
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}

	lvr := ucplugin.LoadVoteResults{
		BestBlock: bestBlock,
	}
	payload, err := ucplugin.EncodeLoadVoteResults(lvr)
	if err != nil {
		return nil, err
	}

	pc := pd.PluginCommand{
		Challenge: hex.EncodeToString(challenge),
		ID:        ucplugin.ID,
		Command:   ucplugin.CmdLoadVoteResults,
		CommandID: ucplugin.CmdLoadVoteResults,
		Payload:   string(payload),
	}

	// Send plugin command to politeiad
	respBody, err := p.makeRequest(http.MethodPost,
		pd.PluginCommandRoute, pc)
	if err != nil {
		return nil, err
	}

	// Handle response
	var pcr pd.PluginCommandReply
	err = json.Unmarshal(respBody, &pcr)
	if err != nil {
		return nil, err
	}

	err = util.VerifyChallenge(p.cfg.Identity, challenge, pcr.Response)
	if err != nil {
		return nil, err
	}

	b := []byte(pcr.Payload)
	reply, err := ucplugin.DecodeLoadVoteResultsReply(b)
	if err != nil {
		spew.Dump("here")
		return nil, err
	}

	return reply, nil
}

// utopiaVoteSummary uses the UtopiaCoinOrg plugin vote summary command to request a
// vote summary for a specific proposal from the cache.
func (p *politeiawww) utopiaVoteSummary(token string) (*ucplugin.VoteSummaryReply, error) {
	v := ucplugin.VoteSummary{
		Token: token,
	}
	payload, err := ucplugin.EncodeVoteSummary(v)
	if err != nil {
		return nil, err
	}

	pc := cache.PluginCommand{
		ID:             ucplugin.ID,
		Command:        ucplugin.CmdVoteSummary,
		CommandPayload: string(payload),
	}

	resp, err := p.cache.PluginExec(pc)
	if err != nil {
		return nil, err
	}

	reply, err := ucplugin.DecodeVoteSummaryReply([]byte(resp.Payload))
	if err != nil {
		return nil, err
	}

	return reply, nil
}
