// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright 2019, TIBCO Software Inc. This file is subject to the license
// terms contained in the license file that is distributed with this file.

package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"git.tibco.com/git/engops/go/vulnrep"
)

type toConvert struct {
	input  string
	output string
	help   bool
}

func (tc *toConvert) parseArgs(appName string, args []string) error {

	fs := flag.NewFlagSet(appName, flag.ContinueOnError)
	fs.StringVar(&tc.input, "input", "", "file to parse for conversion")
	fs.StringVar(&tc.output, "output", "", "output destination")
	fs.BoolVar(&tc.help, "h", false, "set this flag for help.")

	err := fs.Parse(args)
	if err != nil {
		return err
	}
	if tc.help {
		fs.PrintDefaults()
		return nil
	}
	if tc.input == "" {
		return fmt.Errorf("must specify an input file with the -input parameter")
	}

	return nil
}

func parseXMLFile(fName string) (vulnrep.Report, error) {
	f, err := os.Open(fName)
	if err != nil {
		return vulnrep.Report{}, err
	}
	defer f.Close()

	return vulnrep.ParseXML(f)

}
func parseJSONFile(fName string) (vulnrep.Report, error) {
	f, err := os.Open(fName)
	if err != nil {
		return vulnrep.Report{}, err
	}
	defer f.Close()

	return vulnrep.ParseJSON(f)

}

func (tc *toConvert) doConversion() error {

	var readFunc func(string) (vulnrep.Report, error)

	ext := filepath.Ext(tc.input)
	switch ext {
	case ".xml":
		readFunc = parseXMLFile
	case ".json":
		readFunc = parseJSONFile
	default:
		return fmt.Errorf("unrecognized file extension %v - don't know how to parse file", ext)
	}

	rep, err := readFunc(tc.input)
	if err != nil {
		return err
	}

	outFunc := rep.ToCSAF
	var out io.Writer
	if tc.output == "" {
		out = os.Stdout
	} else {
		outFile, err := os.Create(tc.output)
		if err != nil {
			return fmt.Errorf("unable to open output file for conversion: %v", err)
		}
		defer outFile.Close()
		out = outFile

		switch filepath.Ext(tc.output) {
		case ".xml":
			outFunc = rep.ToCVRF
		default:
			outFunc = rep.ToCSAF
		}
	}

	return outFunc(out)
}

func (tc *toConvert) run(appName string, args []string) error {
	err := tc.parseArgs(appName, args)
	if err != nil {
		return err
	}

	if tc.help {
		return nil
	}
	return tc.doConversion()
}

func main() {

	app := &toConvert{}
	err := app.run(os.Args[0], os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	os.Exit(0)
}
