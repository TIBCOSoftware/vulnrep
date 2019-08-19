// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright 2019, TIBCO Software Inc. This file is subject to the license
// terms contained in the license file that is distributed with this file.

package vulnrep

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEnumSerialization(t *testing.T) {

	val := PubTypeVendor
	raw, err := json.Marshal(val)
	assert.NoError(t, err)
	assert.EqualValues(t, `"vendor"`, string(raw))
}
