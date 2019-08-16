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
