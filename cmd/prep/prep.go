// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright 2019, TIBCO Software Inc. This file is subject to the license
// terms contained in the license file that is distributed with this file.

// Purpose built command line tool to download and prepare all the appropriate
// schema files used for testing.
package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"

	"github.com/TIBCOSoftware/vulnrep/schemamod"
	"github.com/pkg/errors"
)

// main wraps a call to run, converting any Go error to a message on os.Stderr,
// and an exit code.
func main() {
	err := run(os.Args[0], os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}
	os.Exit(0)
}

// config captures the command line parameters for this program...
type config struct {
	destFolder string
	help       bool
}

// run performs the guts of this command line tool.
func run(appName string, args []string) error {
	cfg, err := parseArgs(appName, args)
	if err != nil || cfg == nil {
		return err
	}

	return prepFiles(cfg.destFolder)
}

func parseArgs(appName string, args []string) (*config, error) {
	fs := flag.NewFlagSet(appName, flag.ContinueOnError)

	var cfg config
	fs.StringVar(&cfg.destFolder, "dest", "prepared",
		"specify a folder into which to download and prepare critical files")
	fs.BoolVar(&cfg.help, "h", false, "show the help for the application")

	err := fs.Parse(args)
	if err != nil {
		fs.PrintDefaults()
		return nil, err
	}

	if cfg.help {
		fs.PrintDefaults()
		return nil, nil
	}
	return &cfg, nil
}

const oasisGitRepoRaw = "https://raw.githubusercontent.com/oasis-tcs/csaf/master/"

type downloads struct {
	source  string
	relDest string
}

func prepFiles(dest string) error {
	allDownloads := []downloads{
		{
			source:  oasisGitRepoRaw + "sandbox/csaf_2.0/json_schema/csaf_json_schema.json",
			relDest: "csaf_schema.json",
		},
	}

	// download all the files we want to download.
	var err error
	for _, dwn := range allDownloads {
		actualDest := filepath.Join(dest, dwn.relDest)
		err = cacheFile(dwn.source, actualDest)
		if err != nil {
			return errors.Wrapf(err, "problem fetching %v", dwn.relDest)
		}
	}

	// modify the JSON schema.
	officialJSONSchema := filepath.Join(dest, "csaf_schema.json")
	modifiedJSONSchema := filepath.Join(dest, "mod_csaf_schema.json")
	return schemamod.AddPropertyNamesToFile(officialJSONSchema, modifiedJSONSchema)
}

func cacheFile(url, f string) error {
	// does the file exist? If it does, do not overwrite it. This lets developers
	// play with updated versions of the cache files, in case that's useful.
	_, err := os.Stat(f)
	if err == nil {
		return nil
	}

	fn := filepath.Base(f)
	parentDir := filepath.Dir(f)
	err = os.MkdirAll(parentDir, 0750)
	if err != nil {
		return errors.Wrapf(err, "unable to open parent dir for caching %v", fn)
	}
	req, err := http.Get(url) //nolint: gosec - we control this URL.
	if err != nil {
		return errors.Wrapf(err, "unable to fetch file %v", fn)
	}
	defer safeReadClose(req.Body)
	raw, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return fmt.Errorf("unable to read file to save as %v: %v", fn, err)
	}
	return ioutil.WriteFile(f, raw, 0664)
}

// safeReadClose just exists to block harmless lint warnings on closing after reading.
func safeReadClose(c io.Closer) {
	c.Close() //nolint
}
