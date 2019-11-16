// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright 2019, TIBCO Software Inc. This file is subject to the license
// terms contained in the license file that is distributed with this file.

package vulnrep

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/pkg/errors"
)

//go:generate go run cmd/genenums/genenums.go -definitions enums.json -destination enums.go

// targetFormat is used during validation to avoid validation checks that do not
// apply to the specific format.
type targetFormat int

const (
	targetCVRF targetFormat = iota
	targetCSAF
)

// validator captures the list of errors and warnings found with the model.
type validator struct {
	Errors []string

	prodMap  map[*Product]bool
	groupMap map[*Group]bool

	target targetFormat
}

func (v *validator) checkProduct(p *Product, from string) {
	if !v.prodMap[p] {
		v.err(fmt.Sprintf("product %v listed from %v not found in report", p.ID, from))
	}

}

func (v *validator) checkProducts(prods []*Product, from string) {
	for _, p := range prods {
		v.checkProduct(p, from)
	}
}

func (v *validator) err(msg string) { v.Errors = append(v.Errors, msg) }

// nonZeroDatee generates an error for zero date values.
func (v *validator) nonZeroDate(t time.Time, msg string) {
	if t.IsZero() {
		v.err(msg)
	}
}

func (v *validator) nonEmptyLen(length int, msg string) {
	if length == 0 {
		v.err(msg)
	}
}

func (v *validator) nonEmptyStr(str string, msg string) {
	if len(str) == 0 {
		v.err(msg)
	}
}

func (v *validator) listOfNonEmptyStr(strs []string, msg string) {
	for _, s := range strs {
		v.nonEmptyStr(s, msg)
	}
}

func (v *validator) urlVal(urlStr string, ctx string) {
	v.nonEmptyStr(urlStr, fmt.Sprintf("empty %v URL", ctx))
	_, err := url.Parse(urlStr)
	if err != nil {
		v.err(fmt.Sprintf("invalid %v URL %v: %v", ctx, urlStr, err))
	}

}

// ProductID is used to identify and reference a specific *Product with the
// scope of a Report.
type ProductID string

// GroupID is used to identify and reference a set of ProductIDs within a Report.
type GroupID string

// RevisionStr represents a revision in the model.
type RevisionStr string

//nolint: gochecknoglobals
var revisonStrRegEx = regexp.MustCompile(`^(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*)){0,3}$`)

// Check verifies that the Revision string is valid according to format.
func (r RevisionStr) check(val *validator, context interface{}) {
	if !revisonStrRegEx.MatchString(string(r)) {
		val.err(fmt.Sprintf("invalid revision string in %T", context))
	}
}

// Report captures the contents of a vulnerability report
type Report struct {
	Meta            Meta
	ProductTree     ProductTree
	Vulnerabilities []Vulnerability
}

const xmlFilePrefx = `<?xml version="1.0" encoding="UTF-8"?>
`

// ToCVRF encodes a report to XML syntax
func (r Report) ToCVRF(w io.Writer) error {

	// check for errors before output, because we should only output correct
	// data.
	val := r.check(targetCVRF)
	if len(val.Errors) > 0 {
		return errors.Errorf("errors encountered before writing: %v",
			strings.Join(val.Errors, ", "))
	}

	// make sure the file has the standard XML header.
	_, err := w.Write([]byte(xmlFilePrefx))
	if err != nil {
		return errors.Wrap(err, "problem writing XML file header")
	}
	v12rep := toReportXML(r)
	xe := xml.NewEncoder(w)
	xe.Indent("", "    ")
	return xe.Encode(v12rep)
}

// ToCSAF writes a Report out to the JSON format. Note that the file is
// checked for errors before it is written, and will not be written if there
// are any compliance issues.
func (r Report) ToCSAF(w io.Writer) error {

	// check for errors before output, because we should only output correct
	// data.
	val := r.check(targetCSAF)
	if len(val.Errors) > 0 {
		return errors.Errorf("errors encountered before writing: %v",
			strings.Join(val.Errors, ", "))
	}

	rj := toReportJSON(r)
	je := json.NewEncoder(w)
	je.SetIndent("", "    ")
	err := je.Encode(rj)
	if err != nil {
		return fmt.Errorf("problem serializing to JSON: %v", err)
	}
	return nil
}

// Check verifies that the report is valid before writing.
func (r *Report) check(targ targetFormat) *validator {

	products := r.ProductTree.allProducts()
	// ensure uniqueness of product IDs
	checkMap := make(map[ProductID]*Product)
	prodMap := make(map[*Product]bool)
	var errs []string
	for _, prod := range products {
		if matchProd := checkMap[prod.ID]; matchProd == nil {
			checkMap[prod.ID] = prod
		} else {
			if matchProd == prod {
				errs = append(errs, fmt.Sprintf("product %v used multiple times", prod.ID))
			} else {
				errs = append(errs, fmt.Sprintf("repeated product ID %v", prod.ID))
			}
		}
		prodMap[prod] = true
	}

	groupMap := make(map[*Group]bool)
	for _, grp := range r.ProductTree.Groups {
		groupMap[grp] = true
	}

	val := &validator{
		Errors:   errs,
		prodMap:  prodMap,
		groupMap: groupMap,
		target:   targ,
	}

	r.Meta.check(val)
	r.ProductTree.check(val)
	for _, vuln := range r.Vulnerabilities {
		vuln.check(val)
	}

	return val
}

// Meta captures the metadata about a vulnerability report.
type Meta struct {
	Title             string
	Type              string
	Publisher         Publisher
	Tracking          Tracking
	Notes             []Note
	Distribution      string
	AggregateSeverity *AggregateSeverity
	References        []Reference
	Acknowledgments   []Acknowledgment
}

// Check identifies all the possible errors with the ReportMeta information.
func (rm *Meta) check(val *validator) {
	val.nonEmptyStr(rm.Title, "title must not be empty")
	val.nonEmptyStr(rm.Type, "type must not be empty")
	rm.Publisher.check(val)
	rm.Tracking.check(val)

	// check aggregate severity
	if rm.AggregateSeverity != nil {
		rm.AggregateSeverity.check(val)
	}
	// check references
	for _, ref := range rm.References {
		ref.check(val)
	}

	for _, ack := range rm.Acknowledgments {
		ack.check(val)
	}
}

// Cleanup resets ordinals on all notes so that they follow
// expectations from the specification.
// func (rm *ReportMeta) Cleanup() {
// 	for i := range rm.Notes {
// 		rm.Notes[i].Ordinal = i + 1
// 	}
// }

// Tracking captures the tracking data for a CVRF document
type Tracking struct {
	ID                 string
	Aliases            []string
	Status             DocStatus
	Version            RevisionStr
	Revisions          []Revision
	InitialReleaseDate time.Time
	CurrentReleaseDate time.Time
	Generator          *Generator
}

// Generator captures the optional information about the tool that generated
// the vulnerability report. Note that this API inserts no value for Generator
// by default, as this is just an API to be used.
type Generator struct {
	Engine string
	Date   time.Time
}

func (t Tracking) check(val *validator) {
	val.nonEmptyStr(t.ID, "document ID must not be empty")
	val.listOfNonEmptyStr(t.Aliases, "alias IDs must not be empty")
	t.Status.check(val)
	t.Version.check(val, "invalid document version")
	val.nonEmptyLen(len(t.Revisions), "must have at least one document revision")
	for _, rev := range t.Revisions {
		rev.check(val)
	}
	val.nonZeroDate(t.InitialReleaseDate, "initial release date not set")
	val.nonZeroDate(t.CurrentReleaseDate, "current release date not set")
	// no constraints on GeneratorEngine or GeneratorDate

}

// Publisher captures information about who published the document
type Publisher struct {
	Type             PublisherType
	VendorID         string
	ContactDetails   string
	IssuingAuthority string
}

// Check makes sure that the Publisher information conforms to constraints.
func (p Publisher) check(val *validator) {
	p.Type.check(val)
	// note - contact details and issuing authority can be empty strings
	// todo - check for valid vendor ID?
}

// Reference captures reference information
type Reference struct {
	Type        ReferenceType
	URL         string
	Description string
}

// Check verifies that a reference is correct.
func (r *Reference) check(val *validator) {
	r.Type.check(val)
	val.nonEmptyStr(r.Description, "empty description for a reference")
	val.urlVal(r.URL, "reference")
}

// Revision captures the xml representation of document revisions.
type Revision struct {
	Number      RevisionStr
	Date        time.Time
	Description string
}

// Check verifies the document Revision.
func (r Revision) check(val *validator) {
	r.Number.check(val, "revision str not valid for document revision")
	val.nonEmptyStr(r.Description,
		fmt.Sprintf("description not valid for document revision %v", r.Number))
	// XMLSchema of CVRF indicates no revision date required.
	//val.nonZeroDate(r.Date, "revision date not specified")
}

// Note captures notes about either a vulnerability, or about a vulnerability report
type Note struct {
	Title    string
	Audience string
	Type     NoteType
	Text     string
}

// Check verifies that a Note is valid.
func (n *Note) check(val *validator) {
	// Title, audience have no constraints
	n.Type.check(val)
	val.nonEmptyStr(n.Text, "note must have text content")
}

// AggregateSeverity captures the publishers declaration of the severity
// of the vulnerabilities defined in the report.
type AggregateSeverity struct {
	Namespace string
	Text      string
}

// Check ensures a valid aggregate severity
func (as *AggregateSeverity) check(val *validator) {
	val.nonEmptyStr(as.Text, "aggregate severity is empty")
	// Namespace may be empty.
	_, err := url.Parse(as.Namespace)
	if err != nil {
		val.err(fmt.Sprintf("invalid namespace specified in severity: %v", err))
	}
}

// Acknowledgment captures acknowledgments for the document.
type Acknowledgment struct {
	Names         []string
	Organizations []string
	Description   string
	URLs          []string
}

// Check ensures that the acknowledgments meet criteria from the spec.
func (a *Acknowledgment) check(val *validator) {
	val.listOfNonEmptyStr(a.Names, "empty name given for acknowledgment")
	val.listOfNonEmptyStr(a.Organizations, "empty organizaton given for acknowledgment")
	val.listOfNonEmptyStr(a.URLs, "empty URLs given for acknowledgment")

	for _, u := range a.URLs {
		_, err := url.Parse(u)
		if err != nil {
			val.err("bad URL for acknowledgment")
		}
	}
}

// ProductTree captures the representation of the product tree
type ProductTree struct {
	// Note that a product should be identified either under Branches
	// or under Products, but not both.
	Branches []Branch

	// Branches with just a product under them, and no other branches.
	Leaves []ProductLeaf

	// List of products for which no Branch information is associated.
	Products []*Product

	// Relationships amongst products
	Relationships []Relationship

	// Groups of products
	Groups []*Group
}

func (pt *ProductTree) allProducts() []*Product {
	var result []*Product // nolint: prealloc
	result = append(result, pt.Products...)
	result = productsFromBranches(pt.Branches, result)
	for _, leaf := range pt.Leaves {
		result = append(result, leaf.Product)
	}
	for _, relation := range pt.Relationships {
		result = append(result, relation.Products...)
	}
	return result
}

// Check verifies that the product tree is correct
func (pt *ProductTree) check(val *validator) {

	for _, br := range pt.Branches {
		br.check(val)
	}
	for _, leaf := range pt.Leaves {
		leaf.check(val)
	}
	val.checkProducts(pt.Products, "product tree")

	for _, rel := range pt.Relationships {
		rel.check(val)
	}

	for _, grp := range pt.Groups {
		grp.check(val)
	}
}

// Branch associates a particular type/name data pairing with all contained
// product definitions.
type Branch struct {
	Name     string
	Type     BranchType
	Branches []Branch
	Leaves   []ProductLeaf
}

func (b *Branch) allProducts(prods []*Product) []*Product {
	prods = productsFromBranches(b.Branches, prods)
	for _, leaf := range b.Leaves {
		prods = append(prods, leaf.Product)
	}
	return prods
}

func productsFromBranches(branches []Branch, list []*Product) []*Product {
	for _, branch := range branches {
		list = branch.allProducts(list)
	}
	return list
}

// Check verifies that the branches are valid
func (b *Branch) check(val *validator) {
	val.nonEmptyStr(b.Name, "invalid branch name")
	b.Type.check(val)
	for _, child := range b.Branches {
		child.check(val)
	}

	for _, leaf := range b.Leaves {
		leaf.check(val)
	}
}

// ProductLeaf captures a branch for a specific product.
type ProductLeaf struct {
	Name    string
	Type    BranchType
	Product *Product
}

// Check verifies that the ProductLeaf is valid
func (pl *ProductLeaf) check(val *validator) {
	val.nonEmptyStr(pl.Name, "invalid branch leaf name")
	pl.Type.check(val)
	pl.Product.check(val)
}

// Product a name and product ID
type Product struct {
	ID   ProductID
	CPE  string
	Name string
}

// Check verifies that a product is valid.
func (p *Product) check(val *validator) {
	val.nonEmptyStr(string(p.ID), "invalid product ID")
	val.nonEmptyStr(p.Name, "invalid product name")
}

// Relationship captures relationships between products.
type Relationship struct {
	Type               RelationshipType
	Reference          *Product
	RelatesToReference *Product
	Products           []*Product
}

func (r Relationship) check(val *validator) {
	r.Type.check(val)
	val.checkProduct(r.Reference, "relationship reference")
	val.checkProduct(r.RelatesToReference, "relationship relates to reference")
	val.checkProducts(r.Products, "relationship products")
}

// Group identifies a group of products with a group id.
type Group struct {
	ID          GroupID
	Description string
	Products    []*Product
}

func (g Group) check(val *validator) {
	val.checkProducts(g.Products, "group "+string(g.ID))
}

// Vulnerability captures the vulnerabilities in the report.
type Vulnerability struct {
	Title           string
	ID              *VulnID
	Notes           []Note
	DiscoveryDate   time.Time
	ReleaseDate     time.Time
	Involvements    []Involvement
	CVE             string
	CWE             *CWE
	Statuses        Status
	Threats         []Threat
	Scores          []Score
	Remediations    []Remediation
	References      []Reference
	Acknowledgments []Acknowledgment
}

func (v *Vulnerability) check(val *validator) {

	// Title, ID, SystemName can be empty
	v.ID.check(val)

	for _, n := range v.Notes {
		n.check(val)
	}
	for _, inv := range v.Involvements {
		inv.check(val)
	}
	// TODO - validate CVE & CWE entries
	v.Statuses.check(val)
	for _, threat := range v.Threats {
		threat.check(val)
	}

	for _, score := range v.Scores {
		score.check(val)
	}

	for _, rem := range v.Remediations {
		rem.check(val)
	}
	for _, ref := range v.References {
		ref.check(val)
	}
	for _, ack := range v.Acknowledgments {
		ack.check(val)
	}
}

// VulnID captures the identifier for a vulnerability in a vendor-specific
// system name.
type VulnID struct {
	SystemName string
	ID         string
}

func (vi *VulnID) check(val *validator) {
	if vi == nil {
		return
	}
	val.nonEmptyStr(vi.SystemName, "vulnerability id system name")
	// oddly enough, the XMLSchema form of this allows the ID to be
	// empty
}

// Involvement captures the involvement of third parties.
type Involvement struct {
	Party       PublisherType
	Status      InvolvementStatusType
	Description string
}

func (i *Involvement) check(val *validator) {
	i.Party.check(val)
	i.Status.check(val)
	// Description can be empty
}

// CWE captures the Common Weakness Enumeration (CWE) associated with a particular
// vulnerability.
//
// See https://cwe.mitre.org/ for details about these values.
type CWE struct {
	ID          string
	Description string
}

// Status captures the different ways that a vulnerability applies to various
// products.
type Status struct {
	Fixed            []*Product
	FirstAffected    []*Product
	KnownAffected    []*Product
	KnownNotAffected []*Product
	FirstFixed       []*Product
	Recommended      []*Product
	LastAffected     []*Product
}

func (s *Status) check(val *validator) {
	val.checkProducts(s.FirstAffected, "first affected")
	val.checkProducts(s.FirstFixed, "first affected")
	val.checkProducts(s.Fixed, "fixed")
	val.checkProducts(s.KnownAffected, "known affected")
	val.checkProducts(s.KnownNotAffected, "known not affected")
	val.checkProducts(s.LastAffected, "last affected")
	val.checkProducts(s.Recommended, "recommended")
}

// Threat captures the XML representation of the threat types
type Threat struct {
	Type        ThreatType
	Description string
	Date        time.Time
	Products    []*Product
	Groups      []*Group
}

func (th *Threat) check(val *validator) {
	th.Type.check(val)
	val.nonEmptyStr(th.Description, "threat description")
	val.checkProducts(th.Products, "threat")
	for _, g := range th.Groups {
		if !val.groupMap[g] {
			val.err(fmt.Sprintf("group %v as a threat but not found in report", g.ID))
		}
	}
}

// Scoring captures V2 & V3 scores.
type Score struct {
	Products   []*Product
	CVSSScores []CVSSScore
}

// check validates the contents of a score set - note that a nil score set is
// allowed.
func (sc *Score) check(val *validator) {
	if sc == nil {
		return
	}
	val.checkProducts(sc.Products, "Scoring")
	val.nonEmptyLen(len(sc.CVSSScores), "no CVSS score specified")

	for _, cvss := range sc.CVSSScores {
		cvss.check(val)
	}
}

func checkScores(scores []Score, val *validator) {
	for _, score := range scores {
		score.check(val)
	}
}

// ScoreSet captures the XML representation of the CVSS v3 scoring.
type CVSSScore struct {
	Version            string
	BaseScore          float64
	TemporalScore      float64
	EnvironmentalScore float64
	Vector             string
}

func (cvss *CVSSScore) check(val *validator) {
	if cvss.Version != "2.0" && cvss.Version != "3.0" && cvss.Version != "3.1" {
		val.err(fmt.Sprintf("invalid CVSS version %v", cvss.Version))
	}
	// CVRF format does not require the CVSS vector.
	if val.target != targetCVRF && cvss.Vector == "" {
		val.err(fmt.Sprintf("empty CVSS vector"))
	}
}

// Remediation captures a remediation of a vulnerability
type Remediation struct {
	Type        RemedyType
	Date        time.Time
	Description string
	Entitlement []string
	Products    []*Product
	Groups      []*Group
	URL         string
}

func (r *Remediation) check(val *validator) {
	r.Type.check(val)
	val.nonEmptyStr(r.Description, "remediation description")
	for _, s := range r.Entitlement {
		val.nonEmptyStr(s, "entitlement")
	}
	// Note that the URL for the Remediation is allowed to be empty - it just
	// won't be serialized.
}
