// Copyright (c) 2017-2019 The UtopiaCoinOrg developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package commands

// SecretCmd pings the politeiawww secret route.
type SecretCmd struct{}

// Execute executes the secret command.
func (cmd *SecretCmd) Execute(args []string) error {
	ue, err := client.Secret()
	if err != nil {
		return err
	}
	return printJSON(ue)
}
