// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright 2019, TIBCO Software Inc. This file is subject to the license
// terms contained in the license file that is distributed with this file.

// Purpose built command line tool to download and prepare all the appropriate
// schema files used for testing.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"

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
	officialJsonSchema := filepath.Join(dest, "csaf_schema.json")
	modifiedJsonSchema := filepath.Join(dest, "mod_csaf_schema.json")
	return addPropertyNamesToJsonSchema(officialJsonSchema, modifiedJsonSchema)
}

func cacheFile(url string, f string) error {

	// does the file exist? If it does, do not overwrite it. This lets developers
	// play with updated versions of the cache files, in case that's useful.
	_, err := os.Stat(f)
	if err == nil {
		return nil
	}

	fn := filepath.Base(f)
	parentDir := filepath.Dir(f)
	err = os.MkdirAll(parentDir, 0777)
	if err != nil {
		return errors.Wrapf(err, "unable to open parent dir for caching %v", fn)
	}
	req, err := http.Get(url) //nolint: gosec
	if err != nil {
		return errors.Wrapf(err, "unable to fetch file %v", fn)
	}
	defer req.Body.Close()
	raw, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return fmt.Errorf("unable to read file to save as %v: %v", fn, err)
	}
	return ioutil.WriteFile(f, raw, 0664)
}

func enforceObjectPropNames(pth string, obj map[string]interface{}) error {
	// does the object have properties, and not have a propertyNames constraint?
	if obj["properties"] != nil && obj["propertyNames"] == nil {
		var propNames []string
		// cast the properties to a map of prop name + definition.
		props, ok := obj["properties"].(map[string]interface{})
		if !ok {
			return errors.Errorf("unable to cast properties to an object structure for %v", pth)
		}
		// loop through all the properties
		for propName, v := range props {

			// add the name of the property
			propNames = append(propNames, propName)
			propPath := pth + "." + propName
			propAttrs, ok := v.(map[string]interface{})
			if !ok {
				return errors.Errorf("unable to get definition of property %v",
					propPath)
			}
			// recurse through the properties.
			enforcePropNames(propPath, propAttrs)
		}

		// now, have all property names, add a "propertyNames" attribute to the
		// object we have...
		enum := make(map[string]interface{})
		enum["enum"] = interface{}(propNames)
		obj["propertyNames"] = interface{}(enum)
	}
	return nil
}

func enforceArrayPropNames(pth string, obj map[string]interface{}) error {
	items, ok := obj["items"].(map[string]interface{})
	if !ok {
		return errors.Errorf("unable to get items of %v", pth)
	}
	return enforceObjectPropNames(pth, items)
}

func enforcePropNames(pth string, obj map[string]interface{}) error {

	t, ok := obj["type"].(string)
	if ok {
		if t == "object" {
			return enforceObjectPropNames(pth, obj)
		} else if t == "array" {
			return enforceArrayPropNames(pth+"[]", obj)
		}
	}
	return nil
}

// addPropertyNamesToJsonSchema walks through a JSON schema, and adds
// propertyName constraints. The resulting schema enforces that only the
// specified properties appear in the output instance document.
//
// For example:
//
// {
//   "properties": {
//     "doc": ...
//   }
// }
//
// ... becomes
//
// {
//   "properties": {
//     "doc": ...
//   },
//   "propertyNames": {
//     "enum": [ "doc" ]
//   }
// }
func addPropertyNamesToJsonSchema(inFile string, outFile string) error {

	schema, err := readGenericJSONFile(inFile)
	if err != nil {
		return err
	}
	err = enforceObjectPropNames("", schema)
	if err != nil {
		return err
	}
	if schema["definitions"] != nil {
		defs := schema["definitions"].(map[string]interface{})
		for defName, v := range defs {
			defProps, ok := v.(map[string]interface{})
			if !ok {
				return errors.Errorf("unable to get properties of definition %v", defName)
			}
			enforcePropNames("definitions."+defName, defProps)
		}
	}

	toWrite, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		return errors.Wrap(err, "difficulty marshaling modified schema")
	}
	fmt.Printf("Writing modified schema to %v\n", outFile)
	err = ioutil.WriteFile(outFile, toWrite, 0755)
	if err != nil {
		return errors.Wrap(err, "problem writing file")
	}
	return nil
}

// readGenericJSONFile reads and parses a JSON file into the generic form
// of a map[string]interface{}.
func readGenericJSONFile(inFile string) (map[string]interface{}, error) {
	raw, err := ioutil.ReadFile(inFile)
	if err != nil {
		return nil, err
	}
	var result map[string]interface{}
	err = json.Unmarshal(raw, &result)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to parse json file %v", inFile)
	}
	return result, nil
}
