// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright 2019, TIBCO Software Inc. This file is subject to the license
// terms contained in the license file that is distributed with this file.

package vulnrep

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestXMLRoundTrip(t *testing.T) {

	raw, err := ioutil.ReadFile("test/cvrf-1.2-test-use-everything.xml")
	assert.NoError(t, err)
	r, err := ParseXML(bytes.NewBuffer(raw))
	assert.NoError(t, err)

	// strictly speaking, all these verifications that the doc loaded properly
	// are redundant with marshaling the doc back out, and comparing the results,
	// except that having these tests here helps identify if anything went wrong
	// in the unmarshalling process.
	// verify meta info.
	assert.Len(t, r.Meta.Notes, 2)
	assert.Len(t, r.Meta.References, 2)
	assert.Len(t, r.Meta.Tracking.Revisions, 2)
	assert.Len(t, r.Meta.Tracking.Aliases, 3)

	// verify vulnerabilities
	assert.Len(t, r.Vulnerabilities, 1)
	// verify product tree
	assert.Len(t, r.ProductTree.Products, 2)
	assert.Len(t, r.ProductTree.Groups, 1)
	assert.Len(t, r.ProductTree.Leaves, 1)
	assert.Len(t, r.ProductTree.Branches, 1)
	assert.Len(t, r.ProductTree.Relationships, 1)
	assert.Len(t, r.ProductTree.Relationships[0].Products, 1)
	assert.Len(t, r.ProductTree.Branches[0].Leaves, 2)

	allProds := r.ProductTree.allProducts()
	assert.Len(t, allProds, 6)

	var out bytes.Buffer
	err = r.ToCVRF(&out)
	assert.NoError(t, err)
	orig := string(raw)
	assert.EqualValues(t, orig, out.String())

	var jsonOut bytes.Buffer
	err = r.ToCSAF(&jsonOut)
	assert.NoError(t, err)
}

func cacheFile(url string, f string) error {

	_, err := os.Stat(f)
	if err == nil {
		return nil
	}
	if !os.IsNotExist(err) {
		return err
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

const oasisGitRepoRaw = "https://raw.githubusercontent.com/oasis-tcs/csaf/master/"

func TestCompliantOutput(t *testing.T) {

	_, err := exec.LookPath("jsonschema")
	if err != nil {
		fmt.Printf("Didn't find jsonschema tool, skipping test")
		t.SkipNow()
	}

	jsonSchema := filepath.Join(os.TempDir(), "vulrepschemas", "csaf_schema.json")
	err = cacheFile(oasisGitRepoRaw+"sandbox/csaf_2.0/json_schema/csaf_json_schema.json",
		jsonSchema)

	// TODO - validate output.
	assert.NoError(t, err)

}

// func TestXmlToModel(t *testing.T) {
// 	br := branchXML{
// 		BranchType: BranchVendor,
// 		Name: "Example.com",
// 		Branches: []branchXML{
// 			{
// 				BranchType: BranchProductFamily,
// 				Name: "ProdFamily",
// 			}
// 		}
// 	}
// }

func TestChecks(t *testing.T) {

	rep := Report{
		Vulnerabilities: []Vulnerability{{}},
	}
	val := rep.check()
	assert.True(t, len(val.Errors) > 0)
}
