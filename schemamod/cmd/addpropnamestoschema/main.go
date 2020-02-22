// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright 2020, TIBCO Software Inc. This file is subject to the license
// terms contained in the license file that is distributed with this file.

package main

import (
	"fmt"
	"os"

	"github.com/TIBCOSoftware/vulnrep/schemamod"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "require an input and output file as options.")
		os.Exit(1)
	}

	err := schemamod.AddPropertyNamesToFile(os.Args[1], os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
