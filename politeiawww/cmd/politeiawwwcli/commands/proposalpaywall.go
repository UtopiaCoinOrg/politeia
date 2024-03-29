// Copyright (c) 2017-2019 The UtopiaCoinOrg developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package commands

// ProposalPaywallCmd gets paywall info for the logged in user.
type ProposalPaywallCmd struct{}

// Execute executes the proposal paywall command.
func (cmd *ProposalPaywallCmd) Execute(args []string) error {
	ppdr, err := client.ProposalPaywallDetails()
	if err != nil {
		return err
	}
	return printJSON(ppdr)
}

// proposalPaywallHelpMsg is the output of the help command when
// 'proposalpaywall' is specified.
const proposalPaywallHelpMsg = `proposalpaywall

Fetch proposal paywall details.

Arguments: None

Response:
{
  "creditprice"          (uint64)  Price per proposal credit in atoms
  "paywalladdress"       (string)  Proposal paywall address
  "paywalltxnotbefore"   (string)  Minimum timestamp for paywall tx
}`
