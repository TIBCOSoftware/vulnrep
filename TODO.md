# To Do Items

## Open Source

- [x] LICENSE.md
- [x] license on source files
- [x] README.md
- [x]Correct years in copyright statements

## Missing Functionality

- [x] Read JSON data in, validate before returning
- [ ] Language support

## Design Improvements

- [ ] Generated ProductID? (Do they even need to be a part of the API?)
- [ ] Generated GroupIDs (Do they even need to ve part of the API?)
- [ ] Generated ordinals?
- [ ] Change JSON product tree serialization to be a flat list of products with
  properties?
- [ ] Non-pubic AffectedStatusType (only needed for XML serialization)
- [ ] Review struct names for possible improvement
- [ ] Natural Go API for building a vulnerability representation
- [ ] When there are errors after loading a JSON version, better information for
  locating those errors
- [ ] Attempt export of individual vulnerabilities to MITRE's CVE JSON format
- [ ] Rename "ReportMeta" to --> Meta
- [ ] Remove unneeded public types:
  - [ ] Collapse Publisher into Meta
  - [ ] Collapse Tracking into Meta

## Quality Improvements

- [x] fix issues from golangci-lint --enable-all
- [ ] CPE validation
- [ ] CWE validation
- [ ] CVSS validation
  - [ ] valid CVSS vector
  - [ ] correct score

## Doc Improvement

- [ ] add doc.go for package level documentation
- [ ] documentation of the public types

## Test Cases

- [ ] test cases for every enumerated value
- [ ] Full coverage with test cases
- [ ] verify "omitempty" markup (XML mostly) by creating stripped down XML files
- [ ] test output to ensure that it only uses standard properties in JSON?
- [ ] verify that Reports generate in Go, when serialized, validate against JSON
  schema and XML Schema.

## Proposed Changes

- [ ] Drop "ordinal" from JSON output (applies to vulnerabilities and notes)?
- [ ] use JSON schema for CVSS?
- [ ] Change CVSSScoreSets to just "Scoring" in JSON, with children for v3.0 v3.1,
  etc.
- [ ] Why does Relationship include a _list_ of products?
