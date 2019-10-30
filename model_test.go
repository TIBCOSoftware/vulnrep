// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright 2019, TIBCO Software Inc. This file is subject to the license
// terms contained in the license file that is distributed with this file.

package vulnrep

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xeipuuv/gojsonschema"
)

// TestXMLRoundTrip verifies that the library can load a CVRF document, and
// serialize it back out to XML that is identical to the original input document.
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
	// Note: This equivalence test relies heavily on a carefully constructed
	// input document. XML documents can have all sorts of variation, and still
	// be considered semantically equivalent. Differences could include:
	//  * comments
	//  * attribute order
	//  * spaces and indentation
	//  * namespace declarations
	//
	// The input document has been created to match the details of Go's XML
	// marshaling. If that marshaling logic changes, this test could start
	// failing.
	assert.EqualValues(t, orig, out.String())

	var jsonOut bytes.Buffer
	err = r.ToCSAF(&jsonOut)
	assert.NoError(t, err)
}

func TestPartialXMLRoundTrip(t *testing.T) {
	raw, err := ioutil.ReadFile("test/cvrf-1.2-test-remove-once.xml")
	assert.NoError(t, err)
	r, err := ParseXML(bytes.NewBuffer(raw))
	assert.NoError(t, err)

	var out bytes.Buffer
	err = r.ToCVRF(&out)
	assert.NoError(t, err)
	orig := string(raw)
	// Note: See TestXMLRoundTrip for the merits of this test.
	assert.EqualValues(t, orig, out.String())

	var jsonOut bytes.Buffer
	err = r.ToCSAF(&jsonOut)
	assert.NoError(t, err)
}

// fileToURLStr exists to generate a URL from a file, for the purpose of passing
// a URL string to the gojsonschema API.
func fileToURLStr(f string) string {
	url := url.URL{
		Scheme: "file",
		Path:   filepath.ToSlash(f),
	}
	return url.String()
}

// failIfNotPrepped will fail tests if the necessary files have not been downloaded
// and modified appropriately. (See cmd/prep/prep.go)
//
// This solves a bunch of problems:
// * schemas are not baked into the source for this library.
// * developers can replace the downloaded files, to improve the quality of the
//   schemas
// * "prep" operation happens only once, so that unit tests can run quickly.
//
// This is likely not the most elegant solution to this problem.
func failIfNotPrepped(t *testing.T, necessaryFiles ...string) {

	t.Helper()
	for _, f := range necessaryFiles {
		_, err := os.Stat(f)
		if os.IsNotExist(err) {
			t.Fatalf("unable to find file %v - perform 'go run cmd/prep/prep.go' "+
				"to download and modify appropriate files", f)
		}
	}
}

// TestCompliantOutput verifies that the JSON output of a vulnerability report
// actually conforms to the JSON schema specification.
func TestCompliantOutput(t *testing.T) {

	failIfNotPrepped(t, "prepared/mod_csaf_schema.json")
	modifiedJSONSchema, err := filepath.Abs("prepared/mod_csaf_schema.json")
	assert.NoError(t, err)

	raw, err := ioutil.ReadFile("test/cvrf-1.2-test-use-everything.xml")
	assert.NoError(t, err)
	r, err := ParseXML(bytes.NewBuffer(raw))
	assert.NoError(t, err)

	jsonOut, err := ioutil.TempFile("", "vulnrep_json_test_*.json")
	assert.NoError(t, err)
	outPath := jsonOut.Name()
	assert.NoError(t, r.ToCSAF(jsonOut))
	assert.NoError(t, jsonOut.Close())

	schemaLoader := gojsonschema.NewReferenceLoader(fileToURLStr(modifiedJSONSchema))
	documentLoader := gojsonschema.NewReferenceLoader(fileToURLStr(outPath))
	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
	assert.NoError(t, err)
	assert.True(t, result.Valid())
	if !result.Valid() {
		for _, oneErr := range result.Errors() {
			fmt.Println(oneErr.String())
		}
	}
}

func TestChecks(t *testing.T) {

	rep := Report{
		Vulnerabilities: []Vulnerability{{}},
	}
	val := rep.check()
	assert.True(t, len(val.Errors) > 0)
}
