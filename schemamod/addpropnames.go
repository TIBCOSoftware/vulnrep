// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright 2020, TIBCO Software Inc. This file is subject to the license
// terms contained in the license file that is distributed with this file.

// Package schemamod contains utility functions to modify schemas.
//
// Key functions can be used to add propertyNames to schema. This is intended for
// generating modified versions of a schema to verify strict compliance with only the
// defined properties of the schema.
package schemamod

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
)

// AddPropertyNamesToFile modifieds a JSON schema file, and writes the result
// to a new location. See AddPropertyNames for details.
func AddPropertyNamesToFile(inFile, outFile string) error {
	raw, err := ioutil.ReadFile(inFile) //nolint: gosec - we know we're reading an input file
	if err != nil {
		return err
	}
	out, err := AddPropertyNames(raw)
	if err != nil {
		return fmt.Errorf("problem with input file %v: %w", inFile, err)
	}
	err = ioutil.WriteFile(outFile, out, 0755)
	if err != nil {
		return fmt.Errorf("problem writing file %v: %w", outFile, err)
	}
	return nil
}

// AddPropertyNames walks through a JSON schema contained in the "in" parameter, adding
// propertyName constraints. The resulting schema enforces that only the specified properties
// appear in the output instance document. This is intended to generate schemas that catch
// serialization output mistakes.
//
// Note that existing propertyNames constraints are left unmodified. Also note
// that an extra "//GENERATED" property is added to clearly indicate the additional
// constraints that have been added.
//
// For example:
//
//   {
//     "properties": {
//       "doc": ...
//     }
//   }
//
// ... becomes something like this
//
//   {
//     "properties": {
//       "doc": ...
//     },
//     "propertyNames": {
//       "//GENERATED": "propertyNames constraint generated",
//       "enum": [ "doc" ]
//     }
//   }
func AddPropertyNames(in []byte) ([]byte, error) {
	schema, err := readGenericJSON(in)
	if err != nil {
		return nil, err
	}
	err = enforceObjectPropNames("", schema)
	if err != nil {
		return nil, err
	}
	if schema["definitions"] != nil {
		defs := schema["definitions"].(map[string]interface{})
		for defName, v := range defs {
			defProps, ok := v.(map[string]interface{})
			if !ok {
				return nil,
					fmt.Errorf("unable to get properties of definition %v: %w", defName, err)
			}
			err = enforcePropNames("definitions."+defName, defProps)
			if err != nil {
				return nil, err
			}
		}
	}

	toWrite, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("unable to marshal modified schema: %w", err)
	}
	return toWrite, nil
}

// readGenericJSONFile reads and parses a JSON file into the generic form
// of a map[string]interface{}.
func readGenericJSON(in []byte) (map[string]interface{}, error) {
	var result map[string]interface{}
	err := json.Unmarshal(in, &result)
	if err != nil {
		return nil, fmt.Errorf("unable to parse json file: %w", err)
	}
	return result, nil
}

func enforceObjectPropNames(pth string, obj map[string]interface{}) error {
	// does the object have properties, and not have a propertyNames constraint?
	if obj["properties"] != nil && obj["propertyNames"] == nil {
		var propNames []string
		// cast the properties to a map of prop name + definition.
		props, ok := obj["properties"].(map[string]interface{})
		if !ok {
			return fmt.Errorf("unable to cast properties to an object at %v", pth)
		}
		// loop through all the properties
		for propName, v := range props {
			// add the name of the property
			propNames = append(propNames, propName)
			propPath := pth + "." + propName
			propAttrs, ok := v.(map[string]interface{})
			if !ok {
				return fmt.Errorf("unable to get definition of property %v", propPath)
			}
			// recurse through the properties.
			if err := enforcePropNames(propPath, propAttrs); err != nil {
				return err
			}
		}

		if len(propNames) > 0 {
			// now, have all property names, add a "propertyNames" attribute to the
			// object we have...
			enum := make(map[string]interface{})
			enum["enum"] = interface{}(propNames)
			enum["//GENERATED"] = "propertyNames constraint generated"
			obj["propertyNames"] = interface{}(enum)
		}
	}
	return nil
}

// enforcePropNames sets the "propertyNames" property on a given property.
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

// enforceArrayPropNames ensures that propertyName properties are added to the
// object items of arrays.
func enforceArrayPropNames(pth string, obj map[string]interface{}) error {
	items, ok := obj["items"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("unable to get items of %v", pth)
	}
	return enforceObjectPropNames(pth, items)
}
