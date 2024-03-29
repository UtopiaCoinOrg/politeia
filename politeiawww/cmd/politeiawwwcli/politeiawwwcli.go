// Copyright (c) 2017-2019 The UtopiaCoinOrg developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"net/url"
	"os"

	flags "github.com/jessevdk/go-flags"

	"github.com/UtopiaCoinOrg/politeia/politeiawww/cmd/politeiawwwcli/client"
	"github.com/UtopiaCoinOrg/politeia/politeiawww/cmd/politeiawwwcli/commands"
	"github.com/UtopiaCoinOrg/politeia/politeiawww/cmd/politeiawwwcli/config"
)

type politeiawwwcli struct {
	Options  config.Config // XXX: This is just here for the help message for now
	Commands commands.Cmds
}

func _main() error {
	// Load config
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %v", err)
	}
	commands.SetConfig(cfg)

	// Load client
	c, err := client.New(cfg)
	if err != nil {
		return fmt.Errorf("loading client: %v", err)
	}
	commands.SetClient(c)

	// Get politeiawww CSRF token
	if cfg.CSRF == "" {
		_, err := c.Version()
		if err != nil {
			if _, ok := err.(*url.Error); !ok {
				// A url error likely means that politeiawww is not
				// running. The user may just be trying to print the
				// help message so only return an error if its not
				// a url error.
				return fmt.Errorf("Version: %v", err)
			}
		}
	}

	// Parse subcommand and execute
	var cli politeiawwwcli
	var parser = flags.NewParser(&cli, flags.Default)
	if _, err := parser.Parse(); err != nil {
		flagsErr, ok := err.(*flags.Error)
		if ok && flagsErr.Type == flags.ErrHelp {
			os.Exit(0)
		} else {
			os.Exit(1)
		}
	}

	return nil
}

func main() {
	err := _main()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
