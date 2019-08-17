// Copyright (c) 2017-2019 The UtopiaCoinOrg developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package sharedconfig

import (
	"github.com/UtopiaCoinOrg/ucd/ucutil"
)

const (
	DefaultDataDirname = "data"
)

var (
	DefaultHomeDir = ucutil.AppDataDir("politeiad", false)
)
