// Copyright (c) 2017-2019 The UtopiaCoinOrg developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package commands

import "github.com/UtopiaCoinOrg/politeia/politeiawww/api/www/v1"

// ChangeUsernameCmd changes the username for the logged in user.
type ChangeUsernameCmd struct {
	Args struct {
		Password    string `positional-arg-name:"password"`    // User password
		NewUsername string `positional-arg-name:"newusername"` // New username
	} `positional-args:"true" required:"true"`
}

// Execute executes the change username command.
func (cmd *ChangeUsernameCmd) Execute(args []string) error {
	cu := &v1.ChangeUsername{
		Password:    digestSHA3(cmd.Args.Password),
		NewUsername: cmd.Args.NewUsername,
	}

	// Print request details
	err := printJSON(cu)
	if err != nil {
		return err
	}

	// Send request
	cur, err := client.ChangeUsername(cu)
	if err != nil {
		return err
	}

	// Print response details
	return printJSON(cur)
}

// changeUsernameHelpMsg is the output of the help command when
// 'changeusername' is specified.
var changeUsernameHelpMsg = `changeusername "password" "newusername" 

Change the username for the currently logged in user.

Arguments:
1. password      (string, required)   Current password 
2. newusername   (string, required)   New username  

Request:
{
  "password":      (string)  Current password 
  "newusername":   (string)  New username
}

Response:
{}`
