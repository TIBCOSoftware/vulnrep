// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright 2019, TIBCO Software Inc. This file is subject to the license
// terms contained in the license file that is distributed with this file.

package vulnrep

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"strings"
	"time"

	"github.com/pkg/errors"
)

const (
	// NamespaceV11 is the namespace for the 1.1 version of the cvrfdoc XML format.
	namespaceV11 = "http://www.icasi.org/CVRF/schema/cvrf/1.1"

	// NamespaceV12 is the namespace for the 1.2 version of the cvrfdoc XML format.
	namespaceV12 = "http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/cvrf"
)

// reportV11 is a clone of reportV12, except with different annotations for the fields.
type reportV11 struct {
	XMLName           xml.Name              `xml:"http://www.icasi.org/CVRF/schema/cvrf/1.1 cvrfdoc"`
	Title             string                `xml:"DocumentTitle"`
	Type              string                `xml:"DocumentType"`
	Publisher         publisherExp          `xml:"DocumentPublisher"`
	Tracking          trackingExp           `xml:"DocumentTracking"`
	DocumentNotes     []noteExp             `xml:"DocumentNotes>Note"`
	Distribution      string                `xml:"DocumentDistribution,omitempty"`
	AggregateSeverity *aggregateSeverityExp `xml:"AggregateSeverity,omitempty"`
	References        []referenceExp        `xml:"DocumentReferences>Reference,omitempty"`
	Acknowledgments   []acknowledgmentExp   `xml:"Acknowledgments>Acknowledgment,omitempty"`
	ProductTree       productTreeExp        `xml:"http://www.icasi.org/CVRF/schema/prod/1.1 ProductTree"`
	Vulnerabilities   []vulnerabilityXML    `xml:"http://www.icasi.org/CVRF/schema/vuln/1.1 Vulnerability"`
}

// reportV12 is the root structure for parsing a CVRF XML format document.
type reportV12 struct {
	XMLName           xml.Name              `xml:"http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/cvrf cvrfdoc"`
	Title             string                `xml:"DocumentTitle"`
	Type              string                `xml:"DocumentType"`
	Publisher         publisherExp          `xml:"DocumentPublisher"`
	Tracking          trackingExp           `xml:"DocumentTracking"`
	DocumentNotes     []noteExp             `xml:"DocumentNotes>Note"`
	Distribution      string                `xml:"DocumentDistribution,omitempty"`
	AggregateSeverity *aggregateSeverityExp `xml:"AggregateSeverity,omitempty"`
	References        []referenceExp        `xml:"DocumentReferences>Reference,omitempty"`
	Acknowledgments   []acknowledgmentExp   `xml:"Acknowledgments>Acknowledgment,omitempty"`
	ProductTree       productTreeExp        `xml:"http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/prod ProductTree"`
	Vulnerabilities   []vulnerabilityXML    `xml:"http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/vuln Vulnerability"`
}

// xmlToModel converts the vulnerability report from CVRF (XML format) to the all-
// encompassing internal model.
func (r *reportV12) asReport() (Report, error) {

	meta := Meta{
		Title:             r.Title,
		Type:              r.Type,
		Publisher:         r.Publisher.asPublisher(),
		Tracking:          r.Tracking.asTracking(),
		Notes:             asNotes(r.DocumentNotes),
		Distribution:      r.Distribution,
		AggregateSeverity: r.AggregateSeverity.asAggregateSeverity(),
		References:        asReferences(r.References),
		Acknowledgments:   asAcknowledgments(r.Acknowledgments),
	}

	productTree, ctx := r.ProductTree.asProductTree()

	vulns := make([]Vulnerability, 0, len(r.Vulnerabilities))
	for _, vx := range r.Vulnerabilities {
		vulns = append(vulns, vx.asVulnerability(ctx))
	}

	rep := Report{
		Meta:            meta,
		ProductTree:     productTree,
		Vulnerabilities: vulns}

	return rep, ctx.err()
}

func toReportXML(r Report) reportV12 {

	acks := make([]acknowledgmentExp, 0, len(r.Meta.Acknowledgments))
	for _, ack := range r.Meta.Acknowledgments {
		acks = append(acks, acknowledgmentExp(ack))
	}

	return reportV12{
		Title:             r.Meta.Title,
		Type:              r.Meta.Type,
		Publisher:         toPublisherExp(r.Meta.Publisher),
		Tracking:          toTrackingExp(r.Meta.Tracking),
		DocumentNotes:     toNotesXML(r.Meta.Notes),
		Distribution:      r.Meta.Distribution,
		AggregateSeverity: toAggregateSeverityExp(r.Meta.AggregateSeverity),
		References:        toReferenceExps(r.Meta.References),
		Acknowledgments:   acks,
		ProductTree:       toProductTreeXML(r.ProductTree),
		Vulnerabilities:   toVulnerabilityXMLs(r.Vulnerabilities)}
}

// PublisherXML captures publisher information from a CVRF document
type publisherExp struct {
	Type             expPublisherType `xml:"Type,attr" json:"type"`
	VendorID         string           `xml:"VendorID,attr,omitempty" json:"vendor_id,omitempty"`
	ContactDetails   string           `xml:"ContactDetails,omitempty" json:"contact_details,omitempty"`
	IssuingAuthority string           `xml:"IssuingAuthority,omitempty" json:"issuing_authority,omitempty"`
}

func toPublisherExp(pub Publisher) publisherExp {
	return publisherExp{
		Type:             expPublisherType(pub.Type),
		VendorID:         pub.VendorID,
		ContactDetails:   pub.ContactDetails,
		IssuingAuthority: pub.IssuingAuthority}
}

func (pe publisherExp) asPublisher() Publisher {
	return Publisher{
		Type:             PublisherType(pe.Type),
		VendorID:         pe.VendorID,
		ContactDetails:   pe.ContactDetails,
		IssuingAuthority: pe.IssuingAuthority}
}

func timePtrToTime(t *time.Time) time.Time {
	var result time.Time
	if t != nil {
		result = *t
	}
	return result
}

func timeToTimePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// trackingExp used to import / export tracking data about a vulnerability report.
type trackingExp struct {
	ID                 string        `xml:"Identification>ID" json:"id"`
	Aliases            []string      `xml:"Identification>Alias,omitempty" json:"aliases,omitempty"`
	Status             expDocStatus  `xml:"Status" json:"status"`
	Version            RevisionStr   `xml:"Version" json:"version"`
	Revisions          []revisionExp `xml:"RevisionHistory>Revision" json:"revision_history"`
	InitialReleaseDate *time.Time    `xml:"InitialReleaseDate,omitempty" json:"initial_release_date,omitempty"`
	CurrentReleaseDate *time.Time    `xml:"CurrentReleaseDate,omitempty" json:"current_release_date,omitempty"`
	Generator          *generatorExp `xml:"Generator,omitempty" json:"generator,omitempty"`
}

func toTrackingExp(t Tracking) trackingExp {

	return trackingExp{
		ID:                 t.ID,
		Aliases:            t.Aliases,
		Status:             expDocStatus(t.Status),
		Version:            t.Version,
		Revisions:          toRevisionExps(t.Revisions),
		InitialReleaseDate: timeToTimePtr(t.InitialReleaseDate),
		CurrentReleaseDate: timeToTimePtr(t.CurrentReleaseDate),
		Generator:          toGeneratorExp(t.Generator),
	}
}

func (t trackingExp) asTracking() Tracking {
	convRevs := make([]Revision, 0, len(t.Revisions))
	for _, rev := range t.Revisions {
		convRevs = append(convRevs, Revision(rev))
	}
	return Tracking{
		ID:                 t.ID,
		Aliases:            t.Aliases,
		Status:             DocStatus(t.Status),
		Version:            t.Version,
		Revisions:          convRevs,
		InitialReleaseDate: timePtrToTime(t.InitialReleaseDate),
		CurrentReleaseDate: timePtrToTime(t.CurrentReleaseDate),
		Generator:          t.Generator.asGenerator(),
	}
}

type generatorExp struct {
	Engine string     `xml:"Engine,omitempty" json:"engine,omitempty"`
	Date   *time.Time `xml:"Date,omitempty" json:"date,omitempty"`
}

func toGeneratorExp(g *Generator) *generatorExp {
	if g == nil {
		return nil
	}
	return &generatorExp{
		Engine: g.Engine,
		Date:   timeToTimePtr(g.Date)}
}

func (g *generatorExp) asGenerator() *Generator {
	if g == nil {
		return nil
	}
	return &Generator{
		Engine: g.Engine,
		Date:   timePtrToTime(g.Date)}
}

// aggregateSeverityXML captures the aggregate severity information for CVRF document
type aggregateSeverityExp struct {
	Namespace string `xml:"Namespace,attr,omitempty" json:"namespace,omitempty"`
	Text      string `xml:",chardata" json:"text"`
}

func (asx *aggregateSeverityExp) asAggregateSeverity() *AggregateSeverity {
	if asx == nil {
		return nil
	}
	result := AggregateSeverity(*asx)
	return &result
}

func toAggregateSeverityExp(as *AggregateSeverity) *aggregateSeverityExp {
	if as == nil {
		return nil
	}
	result := aggregateSeverityExp(*as)
	return &result
}

// revisionXML captures the xml representation of document revisions.
type revisionExp struct {
	Number      RevisionStr `xml:"Number" json:"number"`
	Date        time.Time   `xml:"Date" json:"date"`
	Description string      `xml:"Description" json:"description"`
}

func toRevisionExps(revs []Revision) []revisionExp {
	result := make([]revisionExp, 0, len(revs))
	for _, rev := range revs {
		result = append(result, revisionExp(rev))
	}
	return result
}

// noteXML captures the document level notes of a CVRF document. Note that
// in the JSON format, the Ordinal field is not read/written.
type noteExp struct {
	Title    string      `xml:"Title,attr,omitempty" json:"title,omitempty"`
	Audience string      `xml:"Audience,attr,omitempty" json:"audience,omitempty"`
	Type     expNoteType `xml:"Type,attr" json:"type"`
	Ordinal  int         `xml:"Ordinal,attr" json:"-"`
	Text     string      `xml:",chardata" json:"text"`
}

func asNotes(notes []noteExp) []Note {
	result := make([]Note, 0, len(notes))
	for _, note := range notes {
		result = append(result, Note{
			Title:    note.Title,
			Audience: note.Audience,
			Type:     NoteType(note.Type),
			Text:     note.Text})
	}
	return result
}

// toNotesXML creates an exportable version of a Note. In the XML format, the
// specification includes an "Ordinal" value which is supposed to be monotonically
// increasing from "1". This routine simply populates based on the index of the
// note.
func toNotesXML(notes []Note) []noteExp {
	result := make([]noteExp, 0, len(notes))
	for idx, note := range notes {
		result = append(result, noteExp{
			Title:    note.Title,
			Audience: note.Audience,
			Type:     expNoteType(note.Type),
			Ordinal:  idx + 1,
			Text:     note.Text})
	}
	return result
}

// referenceXML captures document level references in CVRF
type referenceExp struct {
	Type        expReferenceType `xml:"Type,attr,omitempty" json:"type,omitempty"`
	URL         string           `xml:"URL" json:"url"`
	Description string           `xml:"Description" json:"description"`
}

func asReferences(refs []referenceExp) []Reference {
	result := make([]Reference, 0, len(refs))
	for _, ref := range refs {
		result = append(result, Reference{
			Type:        ReferenceType(ref.Type),
			URL:         ref.URL,
			Description: ref.Description})
	}
	return result
}

func toReferenceExps(refs []Reference) []referenceExp {
	result := make([]referenceExp, 0, len(refs))
	for _, ref := range refs {
		result = append(result, referenceExp{
			Type:        expReferenceType(ref.Type),
			URL:         ref.URL,
			Description: ref.Description})
	}
	return result
}

// acknowledgmentXML captures acknowledgments for the XML format.
type acknowledgmentExp struct {
	Names         []string `xml:"Name" json:"names,omitempty"`
	Organizations []string `xml:"Organization" json:"organizations,omitempty"`
	Description   string   `xml:"Description,omitempty" json:"description,omitempty"`
	URLs          []string `xml:"URL" json:"urls,omitempty"`
}

func toAcknowledgmentExps(acks []Acknowledgment) []acknowledgmentExp {
	result := make([]acknowledgmentExp, 0, len(acks))
	for _, ack := range acks {
		result = append(result, acknowledgmentExp(ack))
	}
	return result
}

func asAcknowledgments(acks []acknowledgmentExp) []Acknowledgment {
	result := make([]Acknowledgment, 0, len(acks))
	for _, ack := range acks {
		result = append(result, Acknowledgment(ack))
	}
	return result
}

// ProductTreeXML captures the XML representation of the CVRF product tree
type productTreeExp struct {
	Branches         []branchExp       `xml:"Branch,omitempty" json:"branches,omitempty"`
	FullProductNames []fullProductExp  `xml:"FullProductName,omitempty" json:"full_product_names"`
	Relationships    []relationshipExp `xml:"Relationship,omitempty" json:"relationships"`
	ProductGroups    []groupExp        `xml:"ProductGroups>Group,omitempty" json:"product_groups"`
}

func toProductTreeXML(pt ProductTree) productTreeExp {

	branches := make([]branchExp, 0, len(pt.Branches)+len(pt.Leaves))
	for _, br := range pt.Branches {
		branches = append(branches, toBranchExp(br))
	}
	for _, leaf := range pt.Leaves {
		branches = append(branches, toSingleBranch(leaf))
	}

	products := make([]fullProductExp, 0, len(pt.Products))
	for _, prd := range pt.Products {
		products = append(products, toFullProductExp(prd))
	}

	relationships := make([]relationshipExp, 0, len(pt.Relationships))
	for _, rel := range pt.Relationships {
		relationships = append(relationships, toRelationshipExp(rel))
	}

	groups := make([]groupExp, 0, len(pt.Groups))
	for _, grp := range pt.Groups {
		groups = append(groups, toGroupExp(*grp))
	}

	return productTreeExp{
		Branches:         branches,
		FullProductNames: products,
		Relationships:    relationships,
		ProductGroups:    groups}
}

// enumProducts gathers all the products listed in FullProductNames, Branches,
// and Relationships, and creates a single list of them
func (ptx *productTreeExp) enumProducts() []*Product {

	var results []*Product //nolint: prealloc
	for _, fp := range ptx.FullProductNames {
		results = append(results, fp.asProduct())
	}

	for _, br := range ptx.Branches {
		results = br.allProducts(results)
	}

	for _, rel := range ptx.Relationships {
		for _, fpn := range rel.FullProductNames {
			results = append(results, fpn.asProduct())
		}
	}
	return results
}

// asProductTree converts a ProductTreeXML structure into a ProductTree,
// mapping data elements as needed.
func (ptx productTreeExp) asProductTree() (ProductTree, *loadCtx) {

	ctx := &loadCtx{
		prodMap:  make(map[ProductID]*Product),
		groupMap: make(map[GroupID]*Group),
	}

	var result ProductTree
	prods := ptx.enumProducts()
	for _, prd := range prods {
		ctx.prodMap[prd.ID] = prd
	}
	// create groups, using the product lookup map.
	for _, xmlGrp := range ptx.ProductGroups {
		newGrp := xmlGrp.asGroup(ctx.prodMap)
		ctx.groupMap[newGrp.ID] = newGrp
		result.Groups = append(result.Groups, newGrp)
	}

	// convert the top level products to a list of products
	for _, fpn := range ptx.FullProductNames {
		result.Products = append(result.Products, ctx.prodMap[fpn.ProductID])
	}

	// convert the "branches" into branches and leaves.
	result.Branches, result.Leaves = asBranchesAndLeaves(ctx.prodMap, ptx.Branches)

	// convert relationships
	for _, rel := range ptx.Relationships {
		result.Relationships = append(result.Relationships,
			rel.asRelationship(ctx))
	}
	return result, ctx
}

func asBranchesAndLeaves(prods map[ProductID]*Product,
	expBranches []branchExp) ([]Branch, []ProductLeaf) {
	var resultLeaves []ProductLeaf
	var resultBranches []Branch
	for _, branch := range expBranches {
		if branch.Product != nil {

			// find the product from the first round of gathering, so we're using the
			// same instance of the product, rather than creating a new one.
			foundProd := prods[branch.Product.ProductID]
			toAdd := ProductLeaf{
				Name:    branch.Name,
				Type:    BranchType(branch.Type),
				Product: foundProd}
			resultLeaves = append(resultLeaves, toAdd)
		} else {
			childBranches, childLeaves := asBranchesAndLeaves(prods, branch.Branches)
			toAdd := Branch{
				Name:     branch.Name,
				Type:     BranchType(branch.Type),
				Branches: childBranches,
				Leaves:   childLeaves}
			resultBranches = append(resultBranches, toAdd)
		}
	}
	return resultBranches, resultLeaves
}

// branchXML captures the XML representation of branches in the product tree
type branchExp struct {
	Type     expBranchType   `xml:"Type,attr" json:"type"`
	Name     string          `xml:"Name,attr" json:"name"`
	Branches []branchExp     `xml:"Branch,omitempty" json:"branches,omitempty"`
	Product  *fullProductExp `xml:"FullProductName,omitempty" json:"product,omitempty"`
}

func toBranchExp(br Branch) branchExp {
	branches := make([]branchExp, 0, len(br.Branches)+len(br.Leaves))
	for _, child := range br.Branches {
		branches = append(branches, toBranchExp(child))
	}
	for _, leaf := range br.Leaves {
		branches = append(branches, toSingleBranch(leaf))
	}
	return branchExp{
		Name:     br.Name,
		Type:     expBranchType(br.Type),
		Branches: branches,
		Product:  nil}
}

func toSingleBranch(leaf ProductLeaf) branchExp {

	prod := toFullProductExp(leaf.Product)
	return branchExp{
		Name:     leaf.Name,
		Type:     expBranchType(leaf.Type),
		Branches: nil,
		Product:  &prod}
}

func (bx *branchExp) allProducts(list []*Product) []*Product {
	if bx.Product != nil {
		list = append(list, bx.Product.asProduct())
	} else {
		for _, br := range bx.Branches {
			list = br.allProducts(list)
		}
	}
	return list
}

// fullProductXML captures the XML representation of the full product description
type fullProductExp struct {
	ProductID ProductID `xml:"ProductID,attr" json:"product_id"`
	CPE       string    `xml:"CPE,attr,omitempty" json:"cpe,omitempty"`
	Name      string    `xml:",chardata" json:"name"`
}

func toFullProductExp(prd *Product) fullProductExp {
	return fullProductExp{
		ProductID: prd.ID,
		CPE:       prd.CPE,
		Name:      prd.Name}
}

func (fpx fullProductExp) asProduct() *Product {
	return &Product{
		ID:   fpx.ProductID,
		CPE:  fpx.CPE,
		Name: fpx.Name}
}

// relationshipXML captures the XML representation of the relationship component of
// the product tree.
type relationshipExp struct {
	ProductReference          ProductID           `xml:"ProductReference,attr" json:"product_reference"`
	RelationshipType          expRelationshipType `xml:"RelationType,attr" json:"relationship_type"`
	RelatesToProductReference ProductID           `xml:"RelatesToProductReference,attr" json:"relates_to_product_reference"`
	FullProductNames          []fullProductExp    `xml:"FullProductName" json:"full_product_names"`
}

func toRelationshipExp(rel Relationship) relationshipExp {

	products := make([]fullProductExp, 0, len(rel.Products))
	for _, prd := range rel.Products {
		products = append(products, toFullProductExp(prd))
	}

	return relationshipExp{
		RelationshipType:          expRelationshipType(rel.Type),
		ProductReference:          rel.Reference.ID,
		RelatesToProductReference: rel.RelatesToReference.ID,
		FullProductNames:          products}
}

func (rx relationshipExp) asRelationship(ctx *loadCtx) Relationship {

	prods := make([]*Product, 0, len(rx.FullProductNames))
	for _, fpn := range rx.FullProductNames {
		prods = append(prods, ctx.prodMap[fpn.ProductID])
	}

	return Relationship{
		Type:               RelationshipType(rx.RelationshipType),
		Products:           prods,
		Reference:          ctx.prodMap[rx.ProductReference],
		RelatesToReference: ctx.prodMap[rx.RelatesToProductReference]}
}

// groupXML captures the XML representation of a product grouping.
type groupExp struct {
	GroupID     GroupID     `xml:"GroupID,attr" json:"group_id"`
	Description string      `xml:"Description,omitempty" json:"description,omitempty"`
	ProductIDs  []ProductID `xml:"ProductID" json:"product_ids"` // at least two required
}

func toGroupExp(grp Group) groupExp {
	return groupExp{
		GroupID:     grp.ID,
		Description: grp.Description,
		ProductIDs:  toProductIDs(grp.Products)}
}

func (gx groupExp) asGroup(lookup map[ProductID]*Product) *Group {

	prodList := make([]*Product, 0, len(gx.ProductIDs))
	for _, id := range gx.ProductIDs {
		prodList = append(prodList, lookup[id])
	}

	return &Group{
		Description: gx.Description,
		ID:          gx.GroupID,
		Products:    prodList}
}

// productStatusXML exists so that serialization of an empty list of status
// items results in no element being emitted, rather than having an empty
// <ProductStatuses/> element, which does not conform to the XML Schema.
type productStatusXML struct {
	Statuses []statusXML `xml:"Status"`
}

// vulnerabilityXML captures the XML information of a vulnerability
type vulnerabilityXML struct {
	Ordinal         int                 `xml:"Ordinal,attr"` // positive integer
	Title           string              `xml:"Title,omitempty"`
	ID              *vulnIDExp          `xml:"ID,omitempty"`
	Notes           []noteExp           `xml:"Notes>Note"`
	DiscoveryDate   *time.Time          `xml:"DiscoveryDate,omitempty"`
	ReleaseDate     *time.Time          `xml:"ReleaseDate,omitempty"`
	Involvements    []involvementExp    `xml:"Involvements>Involvement,omitempty"`
	CVE             string              `xml:"CVE,omitempty"`
	CWE             *cweExp             `xml:"CWE,omitempty"`
	Statuses        *productStatusXML   `xml:"ProductStatuses,omitempty"`
	Threats         []threatExp         `xml:"Threats>Threat,omitempty"`
	CVSSScoreSets   *cvssScoreSetsXML   `xml:"CVSSScoreSets,omitempty"`
	Remediations    []remediationExp    `xml:"Remediations>Remediation"`
	References      []referenceExp      `xml:"References>Reference,omitempty"`
	Acknowledgments []acknowledgmentExp `xml:"Acknowledgments>Acknowledgment,omitempty"`
}

//nolint: dupl
func toVulnerabilityXMLs(vulns []Vulnerability) []vulnerabilityXML {

	result := make([]vulnerabilityXML, 0, len(vulns))
	for idx, v := range vulns {
		result = append(result, vulnerabilityXML{
			Ordinal:         idx + 1,
			Title:           v.Title,
			ID:              toVulnIDExp(v.ID),
			Notes:           toNotesXML(v.Notes),
			DiscoveryDate:   timeToTimePtr(v.DiscoveryDate),
			ReleaseDate:     timeToTimePtr(v.ReleaseDate),
			Involvements:    toInvolvementExps(v.Involvements),
			CVE:             v.CVE,
			CWE:             toCWEExp(v.CWE),
			Statuses:        toStatusXML(v.Statuses),
			Threats:         toThreatExps(v.Threats),
			CVSSScoreSets:   toCVSSScoreSetsXML(v.Scores),
			Remediations:    toRemediationExps(v.Remediations),
			References:      toReferenceExps(v.References),
			Acknowledgments: toAcknowledgmentExps(v.Acknowledgments)})
	}
	return result
}

func (vx vulnerabilityXML) asVulnerability(ctx *loadCtx) Vulnerability {

	remediations := make([]Remediation, 0, len(vx.Remediations))
	for _, rm := range vx.Remediations {
		remediations = append(remediations, rm.asRemediation(ctx))
	}

	return Vulnerability{
		Title:           vx.Title,
		ID:              vx.ID.asVulnID(),
		Notes:           asNotes(vx.Notes),
		DiscoveryDate:   timePtrToTime(vx.DiscoveryDate),
		ReleaseDate:     timePtrToTime(vx.ReleaseDate),
		Involvements:    asInvolvements(vx.Involvements),
		CVE:             vx.CVE,
		CWE:             vx.CWE.asCWE(),
		Statuses:        asStatus(ctx, vx.Statuses),
		Threats:         asThreats(ctx, vx.Threats),
		Scores:          asScoreSet(ctx, vx.CVSSScoreSets),
		Remediations:    remediations,
		References:      asReferences(vx.References),
		Acknowledgments: asAcknowledgments(vx.Acknowledgments)}
}

// idXML captures the XML identifier for a vulnerabilIty
type vulnIDExp struct {
	SystemName string `xml:"SystemName,attr" json:"system_name"`
	ID         string `xml:",chardata" json:"text"`
}

func toVulnIDExp(vid *VulnID) *vulnIDExp {
	if vid == nil {
		return nil
	}
	result := vulnIDExp(*vid)
	return &result
}

func (vid *vulnIDExp) asVulnID() *VulnID {
	if vid == nil {
		return nil
	}
	result := VulnID(*vid)
	return &result
}

// cweXML corresponds to the XML serialization of the CWE data.
type cweExp struct {
	ID          string `xml:"ID,attr" json:"id"`
	Description string `xml:",chardata" json:"description"`
}

func toCWEExp(cwe *CWE) *cweExp {
	if cwe == nil {
		return nil
	}
	result := &cweExp{
		ID:          cwe.ID,
		Description: cwe.Description}
	return result
}

func (cwe *cweExp) asCWE() *CWE {
	if cwe == nil {
		return nil
	}
	result := CWE(*cwe)
	return &result
}

// statusExp captures the list of all products with a given status.
type statusXML struct {
	Type       expaffectedStatusType `xml:"Type,attr"`
	ProductIDs []ProductID           `xml:"ProductID"`
}

func oneStatus(result []statusXML, ast affectedStatusType, prods []*Product) []statusXML {
	if len(prods) == 0 {
		return result
	}
	return append(result, statusXML{Type: expaffectedStatusType(ast),
		ProductIDs: toProductIDs(prods)})
}

func toStatusXML(status Status) *productStatusXML {

	result := oneStatus(nil, affectedStatusFirstAffected, status.FirstAffected)
	result = oneStatus(result, affectedStatusFirstFixed, status.FirstFixed)
	result = oneStatus(result, affectedStatusFixed, status.Fixed)
	result = oneStatus(result, affectedStatusKnownAffected, status.KnownAffected)
	result = oneStatus(result, affectedStatusKnownNotAffected, status.KnownNotAffected)
	result = oneStatus(result, affectedStatusLastAffected, status.LastAffected)
	result = oneStatus(result, affectedStatusRecommended, status.Recommended)

	if len(result) == 0 {
		return nil
	}
	return &productStatusXML{Statuses: result}
}

func asStatus(ctx *loadCtx, statuses *productStatusXML) Status {

	var result Status
	if statuses == nil {
		return result
	}
	for _, st := range statuses.Statuses {
		var list *[]*Product
		var msg string
		switch affectedStatusType(st.Type) {
		case affectedStatusFirstAffected:
			list, msg = &result.FirstAffected, "first affected"
		case affectedStatusFirstFixed:
			list, msg = &result.FirstFixed, "first fixed"
		case affectedStatusFixed:
			list, msg = &result.Fixed, "fixed"
		case affectedStatusKnownAffected:
			list, msg = &result.KnownAffected, "known affected"
		case affectedStatusKnownNotAffected:
			list, msg = &result.KnownNotAffected, "known not affected"
		case affectedStatusLastAffected:
			list, msg = &result.LastAffected, "last affected"
		case affectedStatusRecommended:
			list, msg = &result.Recommended, "recommended"
		}
		*list = append(*list, ctx.asProducts(st.ProductIDs, msg)...)
	}
	return result
}

// ThreatXML captures the XML representation of the threat types
type threatExp struct {
	Type        expThreatType `xml:"Type,attr" json:"type"`
	Description string        `xml:"Description" json:"description"`
	Date        *time.Time    `xml:"Date,attr,omitempty" json:"date,omitempty"`
	ProductIDs  []ProductID   `xml:"ProductID,omitempty" json:"product_ids,omitempty"`
	GroupIDs    []GroupID     `xml:"GroupID,omitempty" json:"group_ids,omitempty"`
}

func toThreatExp(th Threat) threatExp {
	return threatExp{
		Type:        expThreatType(th.Type),
		Description: th.Description,
		Date:        timeToTimePtr(th.Date),
		ProductIDs:  toProductIDs(th.Products),
		GroupIDs:    toGroupIDs(th.Groups)}
}

func toThreatExps(threats []Threat) []threatExp {
	result := make([]threatExp, 0, len(threats))
	for _, th := range threats {
		result = append(result, toThreatExp(th))
	}
	return result
}

func asThreats(ctx *loadCtx, threats []threatExp) []Threat {
	result := make([]Threat, 0, len(threats))
	for _, th := range threats {
		result = append(result, th.asThreat(ctx))
	}
	return result
}

func (tx threatExp) asThreat(ctx *loadCtx) Threat {
	return Threat{
		Type:        ThreatType(tx.Type),
		Description: tx.Description,
		Date:        timePtrToTime(tx.Date),
		Products:    ctx.asProducts(tx.ProductIDs, "threat"),
		Groups:      ctx.asGroups(tx.GroupIDs, "threats"),
	}
}

// CVSSScoreSetsXML captures the XML representation of possible CVSS scores,
// either v2 or v3.
type cvssScoreSetsXML struct {
	ScoreSetV2 []scoreSetV2Exp `xml:"ScoreSetV2,omitempty"`
	ScoreSetV3 []scoreSetV3Exp `xml:"ScoreSetV3,omitempty"`
}

func toCVSSScoreSetsXML(scores []Score) *cvssScoreSetsXML {
	if len(scores) == 0 {
		return nil
	}

	var v2Scores []scoreSetV2Exp
	var v3Scores []scoreSetV3Exp
	for _, score := range scores {
		for _, cvss := range score.CVSSScores {
			prods := toProductIDs(score.Products)
			if cvss.Version == "2.0" {
				v2Scores = append(v2Scores,
					scoreSetV2Exp{
						BaseScore:          cvss.BaseScore,
						TemporalScore:      floatOrNil(cvss.TemporalScore),
						EnvironmentalScore: floatOrNil(cvss.EnvironmentalScore),
						Vector:             cvss.Vector,
						ProductIDs:         prods,
					})
			} else if cvss.Version == "3.0" || cvss.Version == "3.1" {
				v3Scores = append(v3Scores,
					scoreSetV3Exp{
						BaseScore:          cvss.BaseScore,
						Vector:             cvss.Vector,
						EnvironmentalScore: floatOrNil(cvss.EnvironmentalScore),
						TemporalScore:      floatOrNil(cvss.TemporalScore),
						ProductIDs:         prods})
			}
		}
	}

	return &cvssScoreSetsXML{
		ScoreSetV2: v2Scores,
		ScoreSetV3: v3Scores}
}

// scoreSetV2XML captures the XML representation of the CVSS v3 scoring.
type scoreSetV2Exp struct {
	BaseScore          float64     `xml:"BaseScoreV2"`
	TemporalScore      *float64    `xml:"TemporalScoreV2,omitempty"`
	EnvironmentalScore *float64    `xml:"EnvironmentalScoreV2,omitempty"`
	Vector             string      `xml:"VectorV2,omitempty" json:"vector_v2,omitempty"`
	ProductIDs         []ProductID `xml:"ProductID,omitempty" json:"product_ids,omitempty"`
}

// scoreSetV3XML captures the XML representation of the CVSS v3 scoring.
type scoreSetV3Exp struct {
	BaseScore          float64     `xml:"BaseScoreV3"`
	TemporalScore      *float64    `xml:"TemporalScoreV3,omitempty"`
	EnvironmentalScore *float64    `xml:"EnvironmentalScoreV3,omitempty"`
	Vector             string      `xml:"VectorV3,omitempty" json:"vector_v3,omitempty"`
	ProductIDs         []ProductID `xml:"ProductID,omitempty" json:"product_ids,omitempty"`
}

func floatOrNil(f float64) *float64 {
	if f == 0.0 {
		return nil
	}
	res := f
	return &res
}

func unwrapFloat(f *float64) float64 {
	if f == nil {
		return 0.0
	}
	return *f
}

func asScoreSet(ctx *loadCtx, scores *cvssScoreSetsXML) []Score {
	var result []Score // nolint: prealloc
	for _, v2 := range scores.ScoreSetV2 {
		result = append(result, Score{
			Products: ctx.asProducts(v2.ProductIDs, "vulnerability/scores"),
			CVSSScores: []CVSSScore{
				{
					Version:            "2.0",
					BaseScore:          v2.BaseScore,
					Vector:             v2.Vector,
					EnvironmentalScore: unwrapFloat(v2.EnvironmentalScore),
					TemporalScore:      unwrapFloat(v2.TemporalScore),
				},
			}})
	}
	for _, v3 := range scores.ScoreSetV3 {
		result = append(result, Score{
			Products: ctx.asProducts(v3.ProductIDs, "vulnerability/scores"),
			CVSSScores: []CVSSScore{
				{
					Version:            "3.0",
					BaseScore:          v3.BaseScore,
					Vector:             v3.Vector,
					EnvironmentalScore: unwrapFloat(v3.EnvironmentalScore),
					TemporalScore:      unwrapFloat(v3.TemporalScore),
				},
			}})
	}
	return result
}

// remediationExp captures the XML representation for remediations of a vulnerability
type remediationExp struct {
	Type        expRemedyType `xml:"Type,attr" json:"type"`
	Date        *time.Time    `xml:"Date,attr,omitempty" json:"date,omitempty"`
	Description string        `xml:"Description" json:"description"`
	Entitlement []string      `xml:"Entitlement,omitempty" json:"entitlements,omitempty"`
	URL         string        `xml:"URL,omitempty" json:"url,omitempty"`
	Products    []ProductID   `xml:"ProductID,omitempty" json:"product_ids,omitempty"`
	Groups      []GroupID     `xml:"GroupID,omitempty" json:"group_ids,omitempty"`
}

func asRemediations(ctx *loadCtx, remediations []remediationExp) []Remediation {
	result := make([]Remediation, 0, len(remediations))
	for _, rem := range remediations {
		result = append(result, rem.asRemediation(ctx))
	}
	return result
}

func (rem remediationExp) asRemediation(ctx *loadCtx) Remediation {

	return Remediation{
		Type:        RemedyType(rem.Type),
		Date:        timePtrToTime(rem.Date),
		Description: rem.Description,
		Entitlement: rem.Entitlement,
		URL:         rem.URL,
		Products:    ctx.asProducts(rem.Products, "remediation"),
		Groups:      ctx.asGroups(rem.Groups, "remediation"),
	}
}

func toRemediationExp(rem Remediation) remediationExp {
	return remediationExp{
		Type:        expRemedyType(rem.Type),
		Date:        timeToTimePtr(rem.Date),
		Description: rem.Description,
		Entitlement: rem.Entitlement,
		URL:         rem.URL,
		Products:    toProductIDs(rem.Products),
		Groups:      toGroupIDs(rem.Groups),
	}
}

func toRemediationExps(rems []Remediation) []remediationExp {
	result := make([]remediationExp, 0, len(rems))
	for _, rem := range rems {
		result = append(result, toRemediationExp(rem))
	}
	return result
}

type involvementExp struct {
	Party       expPublisherType         `xml:"Party,attr" json:"party"`
	Status      expInvolvementStatusType `xml:"Status,attr" json:"status"`
	Description string                   `xml:"Description,omitempty" json:"description,omitempty"`
}

func asInvolvements(invs []involvementExp) []Involvement {
	result := make([]Involvement, 0, len(invs))
	for _, inv := range invs {
		result = append(result, Involvement{
			Party:       PublisherType(inv.Party),
			Status:      InvolvementStatusType(inv.Status),
			Description: inv.Description})
	}
	return result
}

func toInvolvementExps(invs []Involvement) []involvementExp {
	result := make([]involvementExp, 0, len(invs))
	for _, inv := range invs {
		result = append(result, involvementExp{
			Party:       expPublisherType(inv.Party),
			Status:      expInvolvementStatusType(inv.Status),
			Description: inv.Description})
	}
	return result
}

// ConformanceErr contains identified compliance errors detected during either
// loading or saving a document.
type ConformanceErr struct {
	Issues []string
}

// Error produces one long string for all the conformance errors detected.
func (le *ConformanceErr) Error() string {
	return strings.Join(le.Issues, "\n")
}

type loadCtx struct {
	issues   []string
	prodMap  map[ProductID]*Product
	groupMap map[GroupID]*Group
}

func (lc *loadCtx) err() error {
	if len(lc.issues) == 0 {
		return nil
	}
	return &ConformanceErr{Issues: lc.issues}
}

func (lc *loadCtx) issue(msg string) {
	lc.issues = append(lc.issues, msg)
}

func (lc *loadCtx) asProduct(id ProductID, loc string) *Product {
	prd := lc.prodMap[id]
	if prd == nil {
		lc.issue(fmt.Sprintf("unable to find product id %v for %v", id, loc))
	}
	return prd
}

func (lc *loadCtx) asProducts(list []ProductID, loc string) []*Product {
	result := make([]*Product, 0, len(list))
	for _, id := range list {
		result = append(result, lc.asProduct(id, loc))
	}
	return result
}

func (lc *loadCtx) asGroups(list []GroupID, loc string) []*Group {
	result := make([]*Group, 0, len(list))
	for _, id := range list {
		grp := lc.groupMap[id]
		if grp == nil {
			lc.issue(fmt.Sprintf("unable to find group id %v for %v", id, loc))
		}
		result = append(result, grp)
	}
	return result
}

func (lc *loadCtx) numberAsFloat(val json.Number) float64 {
	result, err := val.Float64()
	if err != nil {
		lc.issue("unrecognized JSON number value")
	}
	return result
}

// ParseXML parses CVRF file. Both CVRF versions 1.1 and 1.2 are supported.
//
// If the parsing process contains only compliance errors, this returns an
// error of type *ComplianceErr, which can be used to access the individual
// issues.
func ParseXML(r io.Reader) (Report, error) {

	var emptyReport Report

	data, err := ioutil.ReadAll(r)
	if err != nil {
		return emptyReport, errors.Wrap(err, "problem opening for parse")
	}

	se, err := firstElement(data)
	if err != nil {
		return emptyReport, err
	}
	if se.Name.Local != "cvrfdoc" {
		return emptyReport, fmt.Errorf("expected root element cvrfdoc, got %v", se.Name.Local)
	}

	var doc reportV12
	if se.Name.Space == namespaceV11 {
		var doc11 reportV11
		err = xml.Unmarshal(data, &doc11)
		// copy over to the 1.2 version of the data.
		doc = reportV12(doc11)
	} else if se.Name.Space == namespaceV12 {
		err = xml.Unmarshal(data, &doc)
	}
	if err != nil {
		return emptyReport, errors.Wrap(err, "problem unmarshalling XML")
	}

	rep, err := doc.asReport()
	if err != nil {
		return rep, err
	}
	return checkCompliance(rep, targetCVRF)
}

func checkCompliance(rep Report, targ targetFormat) (Report, error) {
	val := rep.check(targ)
	if len(val.Errors) > 0 {
		return rep, &ConformanceErr{Issues: val.Errors}
	}
	return rep, nil
}

func firstElement(rawFile []byte) (xml.StartElement, error) {

	buf := bytes.NewBuffer(rawFile)
	d := xml.NewDecoder(buf)
	for {
		t, err := d.Token()
		if err == io.EOF {
			return xml.StartElement{}, errors.New("did not get an element before EOF")
		}
		if err != nil {
			return xml.StartElement{}, err
		}
		if se, ok := t.(xml.StartElement); ok {
			return se, nil
		}
	}
}

func toProductIDs(prods []*Product) []ProductID {
	ids := make([]ProductID, 0, len(prods))
	for _, prd := range prods {
		ids = append(ids, prd.ID)
	}
	return ids
}

func toGroupIDs(grps []*Group) []GroupID {
	ids := make([]GroupID, 0, len(grps))
	for _, grp := range grps {
		ids = append(ids, grp.ID)
	}
	return ids
}
