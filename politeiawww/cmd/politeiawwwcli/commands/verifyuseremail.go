// Copyright (c) 2017-2019 The UtopiaCoinOrg developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package commands

import (
	"encoding/hex"

	"github.com/UtopiaCoinOrg/politeia/politeiawww/api/www/v1"
)

// VerifyUserEmailCmd is used to verify a user's email address.
type VerifyUserEmailCmd struct {
	Args struct {
		Username string `positional-arg-name:"username"` // Username
		Email    string `positional-arg-name:"email"`    // User email address
		Token    string `positional-arg-name:"token"`    // Verification token
	} `positional-args:"true" required:"true"`
}

// Execute executes the verify user email command.
func (cmd *VerifyUserEmailCmd) Execute(args []string) error {
	// Load user identity
	id, err := cfg.LoadIdentity(cmd.Args.Username)
	if err != nil {
		return err
	}

	// Verify user's email address
	sig := id.SignMessage([]byte(cmd.Args.Token))
	vnur, err := client.VerifyNewUser(
		&v1.VerifyNewUser{
			Email:             cmd.Args.Email,
			VerificationToken: cmd.Args.Token,
			Signature:         hex.EncodeToString(sig[:]),
		})
	if err != nil {
		return err
	}

	// Print response details
	return printJSON(vnur)
}

// verifyUserEmailHelpMsg is the output for the help command when
// 'verifyuseremail' is specified.
var verifyUserEmailHelpMsg = `verifyuseremail "email" "token"

Verify user's email address.

Arguments:
1. email       (string, optional)   Email of user
2. token       (string, optional)   Verification token

Result:
{}`
