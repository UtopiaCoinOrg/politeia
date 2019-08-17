// Copyright (c) 2017-2019 The UtopiaCoinOrg developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cockroachdb

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/UtopiaCoinOrg/politeia/ucplugin"
	pd "github.com/UtopiaCoinOrg/politeia/politeiad/api/v1"
	"github.com/UtopiaCoinOrg/politeia/politeiad/cache"
	"github.com/jinzhu/gorm"
)

const (
	// utopiaVersion is the version of the cache implementation of
	// UtopiaCoinOrg plugin. This may differ from the ucplugin package
	// version.
	utopiaVersion = "1.1"

	// UtopiaCoinOrg plugin table names
	tableComments          = "comments"
	tableCommentLikes      = "comment_likes"
	tableCastVotes         = "cast_votes"
	tableAuthorizeVotes    = "authorize_votes"
	tableVoteOptions       = "vote_options"
	tableStartVotes        = "start_votes"
	tableVoteOptionResults = "vote_option_results"
	tableVoteResults       = "vote_results"

	// Vote option IDs
	voteOptionIDApproved = "yes"
)

// UtopiaCoinOrg implements the PluginDriver interface.
type UtopiaCoinOrg struct {
	recordsdb *gorm.DB              // Database context
	version   string                // Version of UtopiaCoinOrg cache plugin
	settings  []cache.PluginSetting // Plugin settings
}

// cmdNewComment creates a Comment record using the passed in payloads and
// inserts it into the database.
func (d *UtopiaCoinOrg) cmdNewComment(cmdPayload, replyPayload string) (string, error) {
	log.Tracef("UtopiaCoinOrg cmdNewComment")

	nc, err := ucplugin.DecodeNewComment([]byte(cmdPayload))
	if err != nil {
		return "", err
	}
	ncr, err := ucplugin.DecodeNewCommentReply([]byte(replyPayload))
	if err != nil {
		return "", err
	}

	c := convertNewCommentFromUtopia(*nc, *ncr)
	err = d.recordsdb.Create(&c).Error

	return replyPayload, err
}

// cmdLikeComment creates a LikeComment record using the passed in payloads
// and inserts it into the database.
func (d *UtopiaCoinOrg) cmdLikeComment(cmdPayload, replyPayload string) (string, error) {
	log.Tracef("UtopiaCoinOrg cmdLikeComment")

	dlc, err := ucplugin.DecodeLikeComment([]byte(cmdPayload))
	if err != nil {
		return "", err
	}

	lc := convertLikeCommentFromUtopia(*dlc)
	err = d.recordsdb.Create(&lc).Error

	return replyPayload, err
}

// cmdCensorComment censors an existing comment.  A censored comment has its
// comment message removed and is marked as censored.
func (d *UtopiaCoinOrg) cmdCensorComment(cmdPayload, replyPayload string) (string, error) {
	log.Tracef("UtopiaCoinOrg cmdCensorComment")

	cc, err := ucplugin.DecodeCensorComment([]byte(cmdPayload))
	if err != nil {
		return "", err
	}

	c := Comment{
		Key: cc.Token + cc.CommentID,
	}
	err = d.recordsdb.Model(&c).
		Updates(map[string]interface{}{
			"comment":  "",
			"censored": true,
		}).Error

	return replyPayload, err
}

func (d *UtopiaCoinOrg) commentGetByID(token string, commentID string) (*Comment, error) {
	c := Comment{
		Key: token + commentID,
	}
	err := d.recordsdb.Find(&c).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			err = cache.ErrRecordNotFound
		}
		return nil, err
	}
	return &c, nil
}

func (d *UtopiaCoinOrg) commentGetBySignature(token string, sig string) (*Comment, error) {
	var c Comment
	err := d.recordsdb.
		Where("token = ? AND signature = ?", token, sig).
		Find(&c).
		Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			err = cache.ErrRecordNotFound
		}
		return nil, err
	}
	return &c, nil
}

// cmdGetComment retreives the passed in comment from the database.
func (d *UtopiaCoinOrg) cmdGetComment(payload string) (string, error) {
	log.Tracef("UtopiaCoinOrg cmdGetComment")

	gc, err := ucplugin.DecodeGetComment([]byte(payload))
	if err != nil {
		return "", err
	}

	if gc.Token == "" {
		return "", cache.ErrInvalidPluginCmdArgs
	}

	var c *Comment
	switch {
	case gc.CommentID != "":
		c, err = d.commentGetByID(gc.Token, gc.CommentID)
	case gc.Signature != "":
		c, err = d.commentGetBySignature(gc.Token, gc.Signature)
	default:
		return "", cache.ErrInvalidPluginCmdArgs
	}
	if err != nil {
		return "", err
	}

	gcr := ucplugin.GetCommentReply{
		Comment: convertCommentToUtopia(*c),
	}
	gcrb, err := ucplugin.EncodeGetCommentReply(gcr)
	if err != nil {
		return "", err
	}

	return string(gcrb), nil
}

// cmdGetComments returns all of the comments for the passed in record token.
func (d *UtopiaCoinOrg) cmdGetComments(payload string) (string, error) {
	log.Tracef("UtopiaCoinOrg cmdGetComments")

	gc, err := ucplugin.DecodeGetComments([]byte(payload))
	if err != nil {
		return "", err
	}

	comments := make([]Comment, 0, 1024) // PNOOMA
	err = d.recordsdb.
		Where("token = ?", gc.Token).
		Find(&comments).
		Error
	if err != nil {
		return "", err
	}

	dpc := make([]ucplugin.Comment, 0, len(comments))
	for _, c := range comments {
		dpc = append(dpc, convertCommentToUtopia(c))
	}

	gcr := ucplugin.GetCommentsReply{
		Comments: dpc,
	}
	gcrb, err := ucplugin.EncodeGetCommentsReply(gcr)
	if err != nil {
		return "", err
	}

	return string(gcrb), nil
}

func (d *UtopiaCoinOrg) cmdGetNumComments(payload string) (string, error) {
	log.Tracef("UtopiaCoinOrg cmdGetNumComments")

	gnc, err := ucplugin.DecodeGetNumComments([]byte(payload))
	if err != nil {
		return "", err
	}

	type Result struct {
		Token  string
		Counts int
	}

	results := make([]Result, 0, 1024)

	err = d.recordsdb.
		Table("comments").
		Select("count(*) as counts, token").
		Group("token").
		Where("token IN (?)", gnc.Tokens).
		Find(&results).
		Error

	if err != nil {
		return "", err
	}

	commentMap := make(map[string]int)
	for _, c := range results {
		commentMap[c.Token] = c.Counts
	}

	gncr := ucplugin.GetNumCommentsReply{
		CommentsMap: commentMap,
	}
	gncre, err := ucplugin.EncodeGetNumCommentsReply(gncr)
	if err != nil {
		return "", err
	}

	return string(gncre), nil
}

// cmdCommentLikes returns all of the comment likes for the passed in comment.
func (d *UtopiaCoinOrg) cmdCommentLikes(payload string) (string, error) {
	log.Tracef("UtopiaCoinOrg cmdCommentLikes")

	cl, err := ucplugin.DecodeCommentLikes([]byte(payload))
	if err != nil {
		return "", err
	}

	likes := make([]LikeComment, 1024) // PNOOMA
	err = d.recordsdb.
		Where("token = ? AND comment_id = ?", cl.Token, cl.CommentID).
		Find(&likes).
		Error
	if err != nil {
		return "", err
	}

	lc := make([]ucplugin.LikeComment, 0, len(likes))
	for _, v := range likes {
		lc = append(lc, convertLikeCommentToUtopia(v))
	}

	clr := ucplugin.CommentLikesReply{
		CommentLikes: lc,
	}
	clrb, err := ucplugin.EncodeCommentLikesReply(clr)
	if err != nil {
		return "", err
	}

	return string(clrb), nil
}

// cmdProposalLikes returns all of the comment likes for all comments of the
// passed in record token.
func (d *UtopiaCoinOrg) cmdProposalCommentsLikes(payload string) (string, error) {
	log.Tracef("UtopiaCoinOrg cmdProposalCommentsLikes")

	cl, err := ucplugin.DecodeGetProposalCommentsLikes([]byte(payload))
	if err != nil {
		return "", err
	}

	likes := make([]LikeComment, 0, 1024) // PNOOMA
	err = d.recordsdb.
		Where("token = ?", cl.Token).
		Find(&likes).
		Error
	if err != nil {
		return "", err
	}

	lc := make([]ucplugin.LikeComment, 0, len(likes))
	for _, v := range likes {
		lc = append(lc, convertLikeCommentToUtopia(v))
	}

	clr := ucplugin.GetProposalCommentsLikesReply{
		CommentsLikes: lc,
	}
	clrb, err := ucplugin.EncodeGetProposalCommentsLikesReply(clr)
	if err != nil {
		return "", err
	}

	return string(clrb), nil
}

// newAuthorizeVote creates an AuthorizeVote record and inserts it into the
// database.  If a previous AuthorizeVote record exists for the passed in
// proposal and version, it will be deleted before the new AuthorizeVote record
// is inserted.
//
// This function must be called within a transaction.
func (d *UtopiaCoinOrg) newAuthorizeVote(tx *gorm.DB, av AuthorizeVote) error {
	// Delete authorize vote if one exists for this version
	err := tx.Where("key = ?", av.Key).
		Delete(AuthorizeVote{}).
		Error
	if err != nil {
		return fmt.Errorf("delete authorize vote: %v", err)
	}

	// Add new authorize vote
	err = tx.Create(&av).Error
	if err != nil {
		return fmt.Errorf("create authorize vote: %v", err)
	}

	return nil
}

// cmdAuthorizeVote creates a AuthorizeVote record using the passed in payloads
// and inserts it into the database.
func (d *UtopiaCoinOrg) cmdAuthorizeVote(cmdPayload, replyPayload string) (string, error) {
	log.Tracef("UtopiaCoinOrg cmdAuthorizeVote")

	av, err := ucplugin.DecodeAuthorizeVote([]byte(cmdPayload))
	if err != nil {
		return "", err
	}
	avr, err := ucplugin.DecodeAuthorizeVoteReply([]byte(replyPayload))
	if err != nil {
		return "", err
	}

	v, err := strconv.ParseUint(avr.RecordVersion, 10, 64)
	if err != nil {
		return "", fmt.Errorf("parse version '%v' failed: %v",
			avr.RecordVersion, err)
	}

	// Run update in a transaction
	a := convertAuthorizeVoteFromUtopia(*av, *avr, v)
	tx := d.recordsdb.Begin()
	err = d.newAuthorizeVote(tx, a)
	if err != nil {
		tx.Rollback()
		return "", fmt.Errorf("newAuthorizeVote: %v", err)
	}

	// Commit transaction
	err = tx.Commit().Error
	if err != nil {
		return "", fmt.Errorf("commit transaction: %v", err)
	}

	return replyPayload, nil
}

// newStartVote inserts a StartVote record into the database.  This function
// has a database parameter so that it can be called inside of a transaction
// when required.
func (d *UtopiaCoinOrg) newStartVote(db *gorm.DB, sv StartVote) error {
	return db.Create(&sv).Error
}

// cmdStartVote creates a StartVote record using the passed in payloads and
// inserts it into the database.
func (d *UtopiaCoinOrg) cmdStartVote(cmdPayload, replyPayload string) (string, error) {
	log.Tracef("UtopiaCoinOrg cmdStartVote")

	sv, err := ucplugin.DecodeStartVote([]byte(cmdPayload))
	if err != nil {
		return "", err
	}
	svr, err := ucplugin.DecodeStartVoteReply([]byte(replyPayload))
	if err != nil {
		return "", err
	}

	endHeight, err := strconv.ParseUint(svr.EndHeight, 10, 64)
	if err != nil {
		return "", fmt.Errorf("parse end height '%v': %v",
			svr.EndHeight, err)
	}

	s := convertStartVoteFromUtopia(*sv, *svr, endHeight)
	err = d.newStartVote(d.recordsdb, s)
	if err != nil {
		return "", err
	}

	return replyPayload, nil
}

// cmdVoteDetails returns the AuthorizeVote and StartVote records for the
// passed in record token.
func (d *UtopiaCoinOrg) cmdVoteDetails(payload string) (string, error) {
	log.Tracef("UtopiaCoinOrg cmdVoteDetails")

	vd, err := ucplugin.DecodeVoteDetails([]byte(payload))
	if err != nil {
		return "", nil
	}

	// Lookup the most recent version of the record
	var r Record
	err = d.recordsdb.
		Where("records.token = ?", vd.Token).
		Order("records.version desc").
		Limit(1).
		Find(&r).
		Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			err = cache.ErrRecordNotFound
		}
		return "", err
	}

	// Lookup authorize vote
	var av AuthorizeVote
	key := vd.Token + strconv.FormatUint(r.Version, 10)
	err = d.recordsdb.
		Where("key = ?", key).
		Find(&av).
		Error
	if err == gorm.ErrRecordNotFound {
		// An authorize vote may note exist. This is ok.
	} else if err != nil {
		return "", fmt.Errorf("authorize vote lookup failed: %v", err)
	}

	// Lookup start vote
	var sv StartVote
	err = d.recordsdb.
		Where("token = ?", vd.Token).
		Preload("Options").
		Find(&sv).
		Error
	if err == gorm.ErrRecordNotFound {
		// A start vote may note exist. This is ok.
	} else if err != nil {
		return "", fmt.Errorf("start vote lookup failed: %v", err)
	}

	// Prepare reply
	dav := convertAuthorizeVoteToUtopia(av)
	dsv, dsvr := convertStartVoteToUtopia(sv)
	vdr := ucplugin.VoteDetailsReply{
		AuthorizeVote:  dav,
		StartVote:      dsv,
		StartVoteReply: dsvr,
	}
	vdrb, err := ucplugin.EncodeVoteDetailsReply(vdr)
	if err != nil {
		return "", err
	}

	return string(vdrb), nil
}

// cmdNewBallot creates CastVote records using the passed in payloads and
// inserts them into the database.
func (d *UtopiaCoinOrg) cmdNewBallot(cmdPayload, replyPayload string) (string, error) {
	log.Tracef("UtopiaCoinOrg cmdNewBallot")

	b, err := ucplugin.DecodeBallot([]byte(cmdPayload))
	if err != nil {
		return "", err
	}

	br, err := ucplugin.DecodeBallotReply([]byte(replyPayload))
	if err != nil {
		return "", err
	}

	// Put votes receipts into a map for easy lookup. Only votes
	// with a receipt signature will be added to the cache.
	receipts := make(map[string]string, len(br.Receipts)) // [clientSig]receiptSig
	for _, v := range br.Receipts {
		receipts[v.ClientSignature] = v.Signature
	}

	// Add cast votes to the cache
	for _, v := range b.Votes {
		// Don't add votes that don't have a receipt signature
		if receipts[v.Signature] == "" {
			log.Debugf("cmdNewBallot: vote receipt not found %v %v",
				v.Token, v.Ticket)
			continue
		}

		cv := convertCastVoteFromUtopia(v)
		err := d.recordsdb.Create(&cv).Error
		if err != nil {
			return "", err
		}
	}

	return replyPayload, nil
}

// cmdProposalVotes returns the StartVote record and all CastVote records for
// the passed in record token.
func (d *UtopiaCoinOrg) cmdProposalVotes(payload string) (string, error) {
	log.Tracef("UtopiaCoinOrg cmdProposalVotes")

	vr, err := ucplugin.DecodeVoteResults([]byte(payload))
	if err != nil {
		return "", err
	}

	// Lookup start vote
	var sv StartVote
	err = d.recordsdb.
		Where("token = ?", vr.Token).
		Preload("Options").
		Find(&sv).
		Error
	if err == gorm.ErrRecordNotFound {
		// A start vote may note exist if the voting period has not
		// been started yet. This is ok.
	} else if err != nil {
		return "", fmt.Errorf("start vote lookup failed: %v", err)
	}

	// Lookup all cast votes
	var cv []CastVote
	err = d.recordsdb.
		Where("token = ?", vr.Token).
		Find(&cv).
		Error
	if err == gorm.ErrRecordNotFound {
		// No cast votes may exist yet. This is ok.
	} else if err != nil {
		return "", fmt.Errorf("cast votes lookup failed: %v", err)
	}

	// Prepare reply
	dsv, _ := convertStartVoteToUtopia(sv)
	dcv := make([]ucplugin.CastVote, 0, len(cv))
	for _, v := range cv {
		dcv = append(dcv, convertCastVoteToUtopia(v))
	}

	vrr := ucplugin.VoteResultsReply{
		StartVote: dsv,
		CastVotes: dcv,
	}

	vrrb, err := ucplugin.EncodeVoteResultsReply(vrr)
	if err != nil {
		return "", err
	}

	return string(vrrb), nil
}

// cmdInventory returns the UtopiaCoinOrg plugin inventory.
func (d *UtopiaCoinOrg) cmdInventory() (string, error) {
	log.Tracef("UtopiaCoinOrg cmdInventory")

	// XXX the only part of the UtopiaCoinOrg plugin inventory that we return
	// at the moment is comments. This is because comments are the only
	// thing politeiawww currently needs on startup.

	// Get all comments
	var c []Comment
	err := d.recordsdb.Find(&c).Error
	if err != nil {
		return "", err
	}

	dc := make([]ucplugin.Comment, 0, len(c))
	for _, v := range c {
		dc = append(dc, convertCommentToUtopia(v))
	}

	// Prepare inventory reply
	ir := ucplugin.InventoryReply{
		Comments: dc,
	}
	irb, err := ucplugin.EncodeInventoryReply(ir)
	if err != nil {
		return "", err
	}

	return string(irb), err
}

// newVoteResults creates a VoteResults record for a proposal and inserts it
// into the cache. A VoteResults record should only be created for proposals
// once the voting period has ended.
func (d *UtopiaCoinOrg) newVoteResults(token string) error {
	log.Tracef("newVoteResults %v", token)

	// Lookup start vote
	var sv StartVote
	err := d.recordsdb.
		Where("token = ?", token).
		Preload("Options").
		Find(&sv).
		Error
	if err != nil {
		return fmt.Errorf("lookup start vote: %v", err)
	}

	// Lookup cast votes
	var cv []CastVote
	err = d.recordsdb.
		Where("token = ?", token).
		Find(&cv).
		Error
	if err == gorm.ErrRecordNotFound {
		// No cast votes exists. In theory, this could
		// happen if no one were to vote on a proposal.
		// In practice, this shouldn't happen.
	} else if err != nil {
		return fmt.Errorf("lookup cast votes: %v", err)
	}

	// Tally cast votes
	tally := make(map[string]uint64) // [voteBit]voteCount
	for _, v := range cv {
		tally[v.VoteBit]++
	}

	// Create vote option results
	results := make([]VoteOptionResult, 0, len(sv.Options))
	for _, v := range sv.Options {
		voteBit := strconv.FormatUint(v.Bits, 16)
		voteCount := tally[voteBit]

		results = append(results, VoteOptionResult{
			Key:    token + voteBit,
			Votes:  voteCount,
			Option: v,
		})
	}

	// Check whether vote was approved
	var total uint64
	for _, v := range results {
		total += v.Votes
	}

	eligible := len(strings.Split(sv.EligibleTickets, ","))
	quorum := uint64(float64(sv.QuorumPercentage) / 100 * float64(eligible))
	pass := uint64(float64(sv.PassPercentage) / 100 * float64(total))

	// XXX: this only supports proposals with yes/no
	// voting options. Multiple voting option support
	// will need to be added in the future.
	var approvedVotes uint64
	for _, v := range results {
		if v.Option.ID == voteOptionIDApproved {
			approvedVotes = v.Votes
		}
	}

	var approved bool
	switch {
	case total < quorum:
		// Quorum not met
	case approvedVotes < pass:
		// Pass percentage not met
	default:
		// Vote was approved
		approved = true
	}

	// Create a vote results entry
	err = d.recordsdb.Create(&VoteResults{
		Token:    token,
		Approved: approved,
		Results:  results,
	}).Error
	if err != nil {
		return fmt.Errorf("new vote results: %v", err)
	}

	return nil
}

// cmdLoadVoteResults creates vote results entries for any proposals that have
// a finished voting period but have not yet been added to the vote results
// table. The vote results table is lazy loaded.
func (d *UtopiaCoinOrg) cmdLoadVoteResults(payload string) (string, error) {
	log.Tracef("cmdLoadVoteResults")

	lvs, err := ucplugin.DecodeLoadVoteResults([]byte(payload))
	if err != nil {
		return "", err
	}

	// Find proposals that have a finished voting period but
	// have not yet been added to the vote results table.
	q := `SELECT start_votes.token
        FROM start_votes
        LEFT OUTER JOIN vote_results
          ON start_votes.token = vote_results.token
          WHERE start_votes.end_height <= ?
          AND vote_results.token IS NULL`
	rows, err := d.recordsdb.Raw(q, lvs.BestBlock).Rows()
	if err != nil {
		return "", fmt.Errorf("no vote results: %v", err)
	}
	defer rows.Close()

	var token string
	tokens := make([]string, 0, 1024)
	for rows.Next() {
		rows.Scan(&token)
		tokens = append(tokens, token)
	}

	// Create vote result entries
	for _, v := range tokens {
		err := d.newVoteResults(v)
		if err != nil {
			return "", fmt.Errorf("newVoteResults %v: %v", v, err)
		}
	}

	// Prepare reply
	r := ucplugin.LoadVoteResultsReply{}
	reply, err := ucplugin.EncodeLoadVoteResultsReply(r)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

// cmdTokenInventory returns the tokens of all records in the cache,
// categorized by stage of the voting process.
func (d *UtopiaCoinOrg) cmdTokenInventory(payload string) (string, error) {
	log.Tracef("UtopiaCoinOrg cmdTokenInventory")

	ti, err := ucplugin.DecodeTokenInventory([]byte(payload))
	if err != nil {
		return "", err
	}

	// The token inventory call cannot be completed if there
	// are any proposals that have finished voting but that
	// don't have an entry in the vote results table yet.
	// Fail here if any are found.
	q := `SELECT start_votes.token
        FROM start_votes
        LEFT OUTER JOIN vote_results
          ON start_votes.token = vote_results.token
          WHERE start_votes.end_height <= ?
          AND vote_results.token IS NULL`
	rows, err := d.recordsdb.Raw(q, ti.BestBlock).Rows()
	if err != nil {
		return "", fmt.Errorf("no vote results: %v", err)
	}
	defer rows.Close()

	var token string
	missing := make([]string, 0, 1024)
	for rows.Next() {
		rows.Scan(&token)
		missing = append(missing, token)
	}

	if len(missing) > 0 {
		// Return a ErrRecordNotFound to indicate one
		// or more vote result records were not found.
		return "", cache.ErrRecordNotFound
	}

	// Pre voting period tokens. This query returns the
	// tokens of the most recent version of all records that
	// are public and do not have an associated StartVote
	// record, ordered by timestamp in descending order.
	q = `SELECT a.token
        FROM records a
        LEFT OUTER JOIN start_votes
          ON a.token = start_votes.token
        LEFT OUTER JOIN records b
          ON a.token = b.token
          AND a.version < b.version
        WHERE b.token IS NULL
          AND start_votes.token IS NULL
          AND a.status = ?
        ORDER BY a.timestamp DESC`
	rows, err = d.recordsdb.Raw(q, pd.RecordStatusPublic).Rows()
	if err != nil {
		return "", fmt.Errorf("pre: %v", err)
	}
	defer rows.Close()

	pre := make([]string, 0, 1024)
	for rows.Next() {
		rows.Scan(&token)
		pre = append(pre, token)
	}

	// Active voting period tokens
	q = `SELECT token
       FROM start_votes
       WHERE end_height > ?
       ORDER BY end_height DESC`
	rows, err = d.recordsdb.Raw(q, ti.BestBlock).Rows()
	if err != nil {
		return "", fmt.Errorf("active: %v", err)
	}
	defer rows.Close()

	active := make([]string, 0, 1024)
	for rows.Next() {
		rows.Scan(&token)
		active = append(active, token)
	}

	// Approved vote tokens
	q = `SELECT vote_results.token
       FROM vote_results
       INNER JOIN start_votes
         ON vote_results.token = start_votes.token
         WHERE vote_results.approved = true
       ORDER BY start_votes.end_height DESC`
	rows, err = d.recordsdb.Raw(q).Rows()
	if err != nil {
		return "", fmt.Errorf("approved: %v", err)
	}
	defer rows.Close()

	approved := make([]string, 0, 1024)
	for rows.Next() {
		rows.Scan(&token)
		approved = append(approved, token)
	}

	// Rejected vote tokens
	q = `SELECT vote_results.token
       FROM vote_results
       INNER JOIN start_votes
         ON vote_results.token = start_votes.token
         WHERE vote_results.approved = false
       ORDER BY start_votes.end_height DESC`
	rows, err = d.recordsdb.Raw(q).Rows()
	if err != nil {
		return "", fmt.Errorf("rejected: %v", err)
	}
	defer rows.Close()

	rejected := make([]string, 0, 1024)
	for rows.Next() {
		rows.Scan(&token)
		rejected = append(rejected, token)
	}

	// Abandoned tokens
	abandoned := make([]string, 0, 1024)
	q = `SELECT token
       FROM records
       WHERE status = ?
       ORDER BY timestamp DESC`
	rows, err = d.recordsdb.Raw(q, pd.RecordStatusArchived).Rows()
	if err != nil {
		return "", fmt.Errorf("abandoned: %v", err)
	}
	defer rows.Close()

	for rows.Next() {
		rows.Scan(&token)
		abandoned = append(abandoned, token)
	}

	// Setup reply
	tir := ucplugin.TokenInventoryReply{
		Pre:       pre,
		Active:    active,
		Approved:  approved,
		Rejected:  rejected,
		Abandoned: abandoned,
	}

	// Add unvetted records if specified
	if ti.Unvetted {
		// Unreviewed tokens. Edits to an unreviewed record do not
		// increment the version. Only edits to a public record
		// increment the version. This means means we don't need
		// to worry about fetching the most recent version here
		// because an unreviewed record will only have one version.
		unreviewed := make([]string, 0, 1024)
		q = `SELECT token
         FROM records
         WHERE status = ? or status = ?
         ORDER BY timestamp DESC`
		rows, err = d.recordsdb.Raw(q, pd.RecordStatusNotReviewed,
			pd.RecordStatusUnreviewedChanges).Rows()
		if err != nil {
			return "", fmt.Errorf("unreviewed: %v", err)
		}
		defer rows.Close()

		for rows.Next() {
			rows.Scan(&token)
			unreviewed = append(unreviewed, token)
		}

		// Censored tokens
		censored := make([]string, 0, 1024)
		q = `SELECT token
         FROM records
         WHERE status = ?
         ORDER BY timestamp DESC`
		rows, err = d.recordsdb.Raw(q, pd.RecordStatusCensored).Rows()
		if err != nil {
			return "", fmt.Errorf("censored: %v", err)
		}
		defer rows.Close()

		for rows.Next() {
			rows.Scan(&token)
			censored = append(censored, token)
		}

		// Update reply
		tir.Unreviewed = unreviewed
		tir.Censored = censored
	}

	// Encode reply
	reply, err := ucplugin.EncodeTokenInventoryReply(tir)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

func (d *UtopiaCoinOrg) cmdVoteSummary(payload string) (string, error) {
	log.Tracef("cmdVoteSummary")

	vs, err := ucplugin.DecodeVoteSummary([]byte(payload))
	if err != nil {
		return "", err
	}

	// Lookup the most recent record version
	var r Record
	err = d.recordsdb.
		Where("records.token = ?", vs.Token).
		Order("records.version desc").
		Limit(1).
		Find(&r).
		Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			err = cache.ErrRecordNotFound
		}
		return "", err
	}

	// Declare here to prevent goto errors
	results := make([]ucplugin.VoteOptionResult, 0, 16)
	var (
		av AuthorizeVote
		sv StartVote
		vr VoteResults
	)

	// Lookup authorize vote
	key := vs.Token + strconv.FormatUint(r.Version, 10)
	err = d.recordsdb.
		Where("key = ?", key).
		Find(&av).
		Error
	if err == gorm.ErrRecordNotFound {
		// If an authorize vote doesn't exist
		// then there is no need to continue.
		goto sendReply
	} else if err != nil {
		return "", fmt.Errorf("lookup authorize vote: %v", err)
	}

	// Lookup start vote
	err = d.recordsdb.
		Where("token = ?", vs.Token).
		Preload("Options").
		Find(&sv).
		Error
	if err == gorm.ErrRecordNotFound {
		// If an start vote doesn't exist then
		// there is no need to continue.
		goto sendReply
	} else if err != nil {
		return "", fmt.Errorf("lookup start vote: %v", err)
	}

	// Lookup vote results
	err = d.recordsdb.
		Where("token = ?", vs.Token).
		Preload("Results").
		Preload("Results.Option").
		Find(&vr).
		Error
	if err == gorm.ErrRecordNotFound {
		// A vote results record was not found. This means that
		// the vote is either still active or has not been lazy
		// loaded yet. The vote results will need to be looked
		// up manually.
	} else if err != nil {
		return "", fmt.Errorf("lookup vote results: %v", err)
	} else {
		// Vote results record exists. We have all of the data
		// that we need to send the reply.
		vor := convertVoteOptionResultsToUtopia(vr.Results)
		results = append(results, vor...)
		goto sendReply
	}

	// Lookup vote results manually
	for _, v := range sv.Options {
		var votes uint64
		tokenVoteBit := v.Token + strconv.FormatUint(v.Bits, 16)
		err := d.recordsdb.
			Model(&CastVote{}).
			Where("token_vote_bit = ?", tokenVoteBit).
			Count(&votes).
			Error
		if err != nil {
			return "", fmt.Errorf("count cast votes: %v", err)
		}

		results = append(results,
			ucplugin.VoteOptionResult{
				ID:          v.ID,
				Description: v.Description,
				Bits:        v.Bits,
				Votes:       votes,
			})
	}

sendReply:
	// Return "" not "0" if end height doesn't exist
	var endHeight string
	if sv.EndHeight != 0 {
		endHeight = strconv.FormatUint(sv.EndHeight, 10)
	}

	vsr := ucplugin.VoteSummaryReply{
		Authorized:          (av.Action == ucplugin.AuthVoteActionAuthorize),
		EndHeight:           endHeight,
		EligibleTicketCount: sv.EligibleTicketCount,
		QuorumPercentage:    sv.QuorumPercentage,
		PassPercentage:      sv.PassPercentage,
		Results:             results,
	}
	reply, err := ucplugin.EncodeVoteSummaryReply(vsr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

// Exec executes a UtopiaCoinOrg plugin command.  Plugin commands that write data to
// the cache require both the command payload and the reply payload.  Plugin
// commands that fetch data from the cache require only the command payload.
// All commands return the appropriate reply payload.
func (d *UtopiaCoinOrg) Exec(cmd, cmdPayload, replyPayload string) (string, error) {
	log.Tracef("UtopiaCoinOrg Exec: %v", cmd)

	switch cmd {
	case ucplugin.CmdAuthorizeVote:
		return d.cmdAuthorizeVote(cmdPayload, replyPayload)
	case ucplugin.CmdStartVote:
		return d.cmdStartVote(cmdPayload, replyPayload)
	case ucplugin.CmdVoteDetails:
		return d.cmdVoteDetails(cmdPayload)
	case ucplugin.CmdBallot:
		return d.cmdNewBallot(cmdPayload, replyPayload)
	case ucplugin.CmdBestBlock:
		return "", nil
	case ucplugin.CmdNewComment:
		return d.cmdNewComment(cmdPayload, replyPayload)
	case ucplugin.CmdLikeComment:
		return d.cmdLikeComment(cmdPayload, replyPayload)
	case ucplugin.CmdCensorComment:
		return d.cmdCensorComment(cmdPayload, replyPayload)
	case ucplugin.CmdGetComment:
		return d.cmdGetComment(cmdPayload)
	case ucplugin.CmdGetComments:
		return d.cmdGetComments(cmdPayload)
	case ucplugin.CmdGetNumComments:
		return d.cmdGetNumComments(cmdPayload)
	case ucplugin.CmdProposalVotes:
		return d.cmdProposalVotes(cmdPayload)
	case ucplugin.CmdCommentLikes:
		return d.cmdCommentLikes(cmdPayload)
	case ucplugin.CmdProposalCommentsLikes:
		return d.cmdProposalCommentsLikes(cmdPayload)
	case ucplugin.CmdInventory:
		return d.cmdInventory()
	case ucplugin.CmdLoadVoteResults:
		return d.cmdLoadVoteResults(cmdPayload)
	case ucplugin.CmdTokenInventory:
		return d.cmdTokenInventory(cmdPayload)
	case ucplugin.CmdVoteSummary:
		return d.cmdVoteSummary(cmdPayload)
	}

	return "", cache.ErrInvalidPluginCmd
}

// createTables creates the cache tables needed by the UtopiaCoinOrg plugin if they do
// not already exist. A UtopiaCoinOrg plugin version record is inserted into the
// database during table creation.
//
// This function must be called within a transaction.
func (d *UtopiaCoinOrg) createTables(tx *gorm.DB) error {
	log.Tracef("createTables")

	// Create UtopiaCoinOrg plugin tables
	if !tx.HasTable(tableComments) {
		err := tx.CreateTable(&Comment{}).Error
		if err != nil {
			return err
		}
	}
	if !tx.HasTable(tableCommentLikes) {
		err := tx.CreateTable(&LikeComment{}).Error
		if err != nil {
			return err
		}
	}
	if !tx.HasTable(tableCastVotes) {
		err := tx.CreateTable(&CastVote{}).Error
		if err != nil {
			return err
		}
	}
	if !tx.HasTable(tableAuthorizeVotes) {
		err := tx.CreateTable(&AuthorizeVote{}).Error
		if err != nil {
			return err
		}
	}
	if !tx.HasTable(tableVoteOptions) {
		err := tx.CreateTable(&VoteOption{}).Error
		if err != nil {
			return err
		}
	}
	if !tx.HasTable(tableStartVotes) {
		err := tx.CreateTable(&StartVote{}).Error
		if err != nil {
			return err
		}
	}
	if !tx.HasTable(tableVoteOptionResults) {
		err := tx.CreateTable(&VoteOptionResult{}).Error
		if err != nil {
			return err
		}
	}
	if !tx.HasTable(tableVoteResults) {
		err := tx.CreateTable(&VoteResults{}).Error
		if err != nil {
			return err
		}
	}

	// Check if a UtopiaCoinOrg version record exists. Insert one
	// if no version record is found.
	if !tx.HasTable(tableVersions) {
		// This should never happen
		return fmt.Errorf("versions table not found")
	}

	var v Version
	err := tx.Where("id = ?", ucplugin.ID).Find(&v).Error
	if err == gorm.ErrRecordNotFound {
		err = tx.Create(
			&Version{
				ID:        ucplugin.ID,
				Version:   utopiaVersion,
				Timestamp: time.Now().Unix(),
			}).Error
	}

	return err
}

// droptTables drops all UtopiaCoinOrg plugin tables from the cache and remove the
// UtopiaCoinOrg plugin version record.
//
// This function must be called within a transaction.
func (d *UtopiaCoinOrg) dropTables(tx *gorm.DB) error {
	// Drop UtopiaCoinOrg plugin tables
	err := tx.DropTableIfExists(tableComments, tableCommentLikes,
		tableCastVotes, tableAuthorizeVotes, tableVoteOptions,
		tableStartVotes, tableVoteOptionResults, tableVoteResults).
		Error
	if err != nil {
		return err
	}

	// Remove UtopiaCoinOrg plugin version record
	return tx.Delete(&Version{
		ID: ucplugin.ID,
	}).Error
}

// build the UtopiaCoinOrg plugin cache using the passed in inventory.
//
// This function cannot be called using a transaction because it could
// potentially exceed cockroachdb's transaction size limit.
func (d *UtopiaCoinOrg) build(ir *ucplugin.InventoryReply) error {
	log.Tracef("UtopiaCoinOrg build")

	// Drop all UtopiaCoinOrg plugin tables
	tx := d.recordsdb.Begin()
	err := d.dropTables(tx)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("drop tables: %v", err)
	}
	err = tx.Commit().Error
	if err != nil {
		return err
	}

	// Create UtopiaCoinOrg plugin tables
	tx = d.recordsdb.Begin()
	err = d.createTables(tx)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("create tables: %v", err)
	}
	err = tx.Commit().Error
	if err != nil {
		return err
	}

	// Build comments cache
	log.Tracef("UtopiaCoinOrg: building comments cache")
	for _, v := range ir.Comments {
		c := convertCommentFromUtopia(v)
		err := d.recordsdb.Create(&c).Error
		if err != nil {
			log.Debugf("create comment failed on '%v'", c)
			return fmt.Errorf("newComment: %v", err)
		}
	}

	// Build like comments cache
	log.Tracef("UtopiaCoinOrg: building like comments cache")
	for _, v := range ir.LikeComments {
		lc := convertLikeCommentFromUtopia(v)
		err := d.recordsdb.Create(&lc).Error
		if err != nil {
			log.Debugf("newLikeComment failed on '%v'", lc)
			return fmt.Errorf("newLikeComment: %v", err)
		}
	}

	// Put authorize vote replies in a map for quick lookups
	avr := make(map[string]ucplugin.AuthorizeVoteReply,
		len(ir.AuthorizeVoteReplies)) // [receipt]AuthorizeVote
	for _, v := range ir.AuthorizeVoteReplies {
		avr[v.Receipt] = v
	}

	// Build authorize vote cache
	log.Tracef("UtopiaCoinOrg: building authorize vote cache")
	for _, v := range ir.AuthorizeVotes {
		r, ok := avr[v.Receipt]
		if !ok {
			return fmt.Errorf("AuthorizeVoteReply not found %v",
				v.Token)
		}

		rv, err := strconv.ParseUint(r.RecordVersion, 10, 64)
		if err != nil {
			log.Debugf("newAuthorizeVote failed on '%v'", r)
			return fmt.Errorf("parse version '%v' failed: %v",
				r.RecordVersion, err)
		}

		av := convertAuthorizeVoteFromUtopia(v, r, rv)
		err = d.newAuthorizeVote(d.recordsdb, av)
		if err != nil {
			log.Debugf("newAuthorizeVote failed on '%v'", av)
			return fmt.Errorf("newAuthorizeVote: %v", err)
		}
	}

	// Build start vote cache
	log.Tracef("UtopiaCoinOrg: building start vote cache")
	for _, v := range ir.StartVoteTuples {
		endHeight, err := strconv.ParseUint(v.StartVoteReply.EndHeight, 10, 64)
		if err != nil {
			log.Debugf("newStartVote failed on '%v'", v)
			return fmt.Errorf("parse end height '%v': %v",
				v.StartVoteReply.EndHeight, err)
		}

		sv := convertStartVoteFromUtopia(v.StartVote,
			v.StartVoteReply, endHeight)
		err = d.newStartVote(d.recordsdb, sv)
		if err != nil {
			log.Debugf("newStartVote failed on '%v'", sv)
			return fmt.Errorf("newStartVote: %v", err)
		}
	}

	// Build cast vote cache
	log.Tracef("UtopiaCoinOrg: building cast vote cache")
	for _, v := range ir.CastVotes {
		cv := convertCastVoteFromUtopia(v)
		err := d.recordsdb.Create(&cv).Error
		if err != nil {
			log.Debugf("insert cast vote failed on '%v'", cv)
			return fmt.Errorf("insert cast vote: %v", err)
		}
	}

	return nil
}

// Build drops all existing UtopiaCoinOrg plugin tables from the database, recreates
// them, then uses the passed in inventory payload to build the UtopiaCoinOrg plugin
// cache.
func (d *UtopiaCoinOrg) Build(payload string) error {
	log.Tracef("UtopiaCoinOrg Build")

	// Decode the payload
	ir, err := ucplugin.DecodeInventoryReply([]byte(payload))
	if err != nil {
		return fmt.Errorf("DecodeInventoryReply: %v", err)
	}

	// Build the UtopiaCoinOrg plugin cache. This is not run using
	// a transaction because it could potentially exceed
	// cockroachdb's transaction size limit.
	err = d.build(ir)
	if err != nil {
		// Remove the version record. This will
		// force a rebuild on the next start up.
		err1 := d.recordsdb.Delete(&Version{
			ID: ucplugin.ID,
		}).Error
		if err1 != nil {
			panic("the cache is out of sync and will not rebuild" +
				"automatically; a rebuild must be forced")
		}
	}

	return err
}

// Setup creates the UtopiaCoinOrg plugin tables if they do not already exist.  A
// UtopiaCoinOrg plugin version record is inserted into the database during table
// creation.
func (d *UtopiaCoinOrg) Setup() error {
	log.Tracef("UtopiaCoinOrg: Setup")

	tx := d.recordsdb.Begin()
	err := d.createTables(tx)
	if err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit().Error
}

// CheckVersion retrieves the UtopiaCoinOrg plugin version record from the database,
// if one exists, and checks that it matches the version of the current UtopiaCoinOrg
// plugin cache implementation.
func (d *UtopiaCoinOrg) CheckVersion() error {
	log.Tracef("UtopiaCoinOrg: CheckVersion")

	// Sanity check. Ensure version table exists.
	if !d.recordsdb.HasTable(tableVersions) {
		return fmt.Errorf("versions table not found")
	}

	// Lookup version record. If the version is not found or
	// if there is a version mismatch, return an error so
	// that the UtopiaCoinOrg plugin cache can be built/rebuilt.
	var v Version
	err := d.recordsdb.
		Where("id = ?", ucplugin.ID).
		Find(&v).
		Error
	if err == gorm.ErrRecordNotFound {
		log.Debugf("version record not found for ID '%v'",
			ucplugin.ID)
		err = cache.ErrNoVersionRecord
	} else if v.Version != utopiaVersion {
		log.Debugf("version mismatch for ID '%v': got %v, want %v",
			ucplugin.ID, v.Version, utopiaVersion)
		err = cache.ErrWrongVersion
	}

	return err
}

// newUtopiaPlugin returns a cache UtopiaCoinOrg plugin context.
func newUtopiaPlugin(db *gorm.DB, p cache.Plugin) *UtopiaCoinOrg {
	log.Tracef("newUtopiaPlugin")
	return &UtopiaCoinOrg{
		recordsdb: db,
		version:   utopiaVersion,
		settings:  p.Settings,
	}
}
