// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright 2020, TIBCO Software Inc. This file is subject to the license
// terms contained in the license file that is distributed with this file.

package schemamod

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const inSchema = `{
  "properties": {
    "name": {
      "type": "string"
    }
  }
}
`

const outSchema = `{
  "properties": {
    "name": {
      "type": "string"
    }
  },
  "propertyNames": {
    "//GENERATED": "propertyNames constraint generated",
    "enum": [
      "name"
    ]
  }
}`

func TestAddPropNames(t *testing.T) {
	out, err := AddPropertyNames([]byte(inSchema))
	assert.NoError(t, err)
	assert.Equal(t, outSchema, string(out))
}
