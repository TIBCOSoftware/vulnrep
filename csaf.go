// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright 2019, TIBCO Software Inc. This file is subject to the license
// terms contained in the license file that is distributed with this file.

package vulnrep

import (
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// ParseJSON reads the JSON format of vulnerability report.
//
// Note that this method validates the input document for compliance before
// returning it (for example, an empty description). All compliance problems are
// flagged as an error.
func ParseJSON(r io.Reader) (Report, error) {
	var emptyReport Report

	var jsonRep reportJSON
	dec := json.NewDecoder(r)
	err := dec.Decode(&jsonRep)
	if err != nil {
		return emptyReport, fmt.Errorf("unable to decode report: %v", err)
	}

	return checkCompliance(jsonRep.asReport())
}

type reportJSON struct {
	Meta            reportMetaJSON      `json:"document"`
	ProductTree     productTreeExp      `json:"product_tree"`
	Vulnerabilities []vulnerabilityJSON `json:"vulnerabilities"`
}

func (rj reportJSON) asReport() (Report, error) {

	meta := Meta{
		Title:             rj.Meta.Title,
		Type:              rj.Meta.Type,
		Publisher:         rj.Meta.Publisher.asPublisher(),
		Tracking:          rj.Meta.Tracking.asTracking(),
		Notes:             asNotes(rj.Meta.Notes),
		Distribution:      rj.Meta.Distribution,
		AggregateSeverity: rj.Meta.AggregateSeverity.asAggregateSeverity(),
		References:        asReferences(rj.Meta.References),
		Acknowledgments:   asAcknowledgments(rj.Meta.Acknowledgments),
	}

	productTree, ctx := rj.ProductTree.asProductTree()
	vulns := make([]Vulnerability, 0, len(rj.Vulnerabilities))
	for _, vj := range rj.Vulnerabilities {
		vulns = append(vulns, vj.asVulnerability(ctx))
	}

	// parse all the metadata for the document
	rep := Report{
		Meta:            meta,
		ProductTree:     productTree,
		Vulnerabilities: vulns}
	return rep, ctx.err()
}

func toReportJSON(rep Report) reportJSON {

	vuls := make([]vulnerabilityJSON, 0, len(rep.Vulnerabilities))
	for _, vul := range rep.Vulnerabilities {
		vuls = append(vuls, toVulnerabilityJSON(vul))
	}
	return reportJSON{
		Meta:            toReportMetaJSON(rep.Meta),
		ProductTree:     toProductTreeXML(rep.ProductTree),
		Vulnerabilities: vuls,
	}
}

// ReportMeta captures the metadata about a vulnerability report
type reportMetaJSON struct {
	Title             string                `json:"title"`
	Type              string                `json:"type"`
	Publisher         publisherExp          `json:"publisher"`
	Tracking          trackingExp           `json:"tracking"`
	Notes             []noteExp             `json:"notes"`
	Distribution      string                `json:"distribution,omitempty"`
	AggregateSeverity *aggregateSeverityExp `json:"aggregate_severity"`
	References        []referenceExp        `json:"references"`
	Acknowledgments   []acknowledgmentExp   `json:"acknowledgments"`
}

func toReportMetaJSON(meta Meta) reportMetaJSON {

	return reportMetaJSON{
		Title:             meta.Title,
		Type:              meta.Type,
		Publisher:         toPublisherExp(meta.Publisher),
		Tracking:          toTrackingExp(meta.Tracking),
		Notes:             toNotesXML(meta.Notes),
		Distribution:      meta.Distribution,
		AggregateSeverity: toAggregateSeverityExp(meta.AggregateSeverity),
		References:        toReferenceExps(meta.References),
		Acknowledgments:   toAcknowledgmentExps(meta.Acknowledgments),
	}
}

type vulnerabilityJSON struct {
	Title           string              `json:"title,omitempty"`
	ID              *vulnIDExp          `json:"id,omitempty"`
	Notes           []noteExp           `json:"notes,omitempty"`
	DiscoveryDate   *time.Time          `json:"discovery_date,omitempty"`
	ReleaseDate     *time.Time          `json:"release_date,omitempty"`
	Involvements    []involvementExp    `json:"involvements,omitempty"`
	CVE             string              `json:"cve,omitempty"`
	CWE             *cweExp             `json:"cwe,omitempty"`
	ProductStatus   productStatusJSON   `json:"product_status"`
	Threats         []threatExp         `json:"threats"`
	CVSS            *cvssScoreSetsJSON  `json:"scores,omitempty"`
	Remediations    []remediationExp    `json:"remediations"`
	References      []referenceExp      `json:"references"`
	Acknowledgments []acknowledgmentExp `json:"acknowledgments"`
}

func (vj vulnerabilityJSON) asVulnerability(ctx *loadCtx) Vulnerability {

	return Vulnerability{
		Title:           vj.Title,
		ID:              vj.ID.asVulnID(),
		Notes:           asNotes(vj.Notes),
		DiscoveryDate:   timePtrToTime(vj.DiscoveryDate),
		ReleaseDate:     timePtrToTime(vj.ReleaseDate),
		Involvements:    asInvolvements(vj.Involvements),
		CVE:             vj.CVE,
		CWE:             vj.CWE.asCWE(),
		Statuses:        vj.ProductStatus.asStatus(ctx),
		Threats:         asThreats(ctx, vj.Threats),
		CVSS:            vj.CVSS.asScoreSet(ctx),
		Remediations:    asRemediations(ctx, vj.Remediations),
		References:      asReferences(vj.References),
		Acknowledgments: asAcknowledgments(vj.Acknowledgments)}
}

//nolint: dupl
func toVulnerabilityJSON(v Vulnerability) vulnerabilityJSON {
	return vulnerabilityJSON{
		Title:           v.Title,
		ID:              toVulnIDExp(v.ID),
		Notes:           toNotesXML(v.Notes),
		DiscoveryDate:   timeToTimePtr(v.DiscoveryDate),
		ReleaseDate:     timeToTimePtr(v.ReleaseDate),
		Involvements:    toInvolvementExps(v.Involvements),
		CVE:             v.CVE,
		CWE:             toCWEExp(v.CWE),
		ProductStatus:   toProductStatusesJSON(v.Statuses),
		Threats:         toThreatExps(v.Threats),
		CVSS:            toCVSSScoreSetsJSON(v.CVSS),
		Remediations:    toRemediationExps(v.Remediations),
		References:      toReferenceExps(v.References),
		Acknowledgments: toAcknowledgmentExps(v.Acknowledgments)}
}

type cvssScoreSetsJSON struct {
	V2 []scoreSetV2Exp `json:"cvss_v20"`
	V3 []scoreSetV3Exp `json:"cvss_v30"`
}

func (ss *cvssScoreSetsJSON) asScoreSet(ctx *loadCtx) *CVSSScoreSets {
	if ss == nil {
		return nil
	}
	return &CVSSScoreSets{
		V2: asScoreSetsV2(ctx, ss.V2),
		V3: asScoreSets(ctx, ss.V3),
	}
}

func toCVSSScoreSetsJSON(ss *CVSSScoreSets) *cvssScoreSetsJSON {
	if ss == nil {
		return nil
	}
	return &cvssScoreSetsJSON{
		V2: toScoreSetV2Exps(ss.V2),
		V3: toScoreSetV3Exps(ss.V3)}
}

type productStatusJSON struct {
	Fixed            []ProductID `json:"fixed,omitempty"`
	FirstAffected    []ProductID `json:"first_affected,omitempty"`
	KnownAffected    []ProductID `json:"known_affected,omitempty"`
	KnownNotAffected []ProductID `json:"known_not_affected,omitempty"`
	FirstFixed       []ProductID `json:"first_fixed,omitempty"`
	Recommended      []ProductID `json:"recommended,omitempty"`
	LastAffected     []ProductID `json:"last_affected,omitempty"`
}

func (psj productStatusJSON) asStatus(ctx *loadCtx) Status {

	return Status{
		Fixed:            ctx.asProducts(psj.Fixed, "status/fixed"),
		FirstAffected:    ctx.asProducts(psj.FirstAffected, "status/first_affected"),
		KnownAffected:    ctx.asProducts(psj.KnownAffected, "status/known_affected"),
		KnownNotAffected: ctx.asProducts(psj.KnownNotAffected, "status/known_not_affected"),
		FirstFixed:       ctx.asProducts(psj.FirstFixed, "status/first_fixed"),
		Recommended:      ctx.asProducts(psj.Recommended, "status/recommended"),
		LastAffected:     ctx.asProducts(psj.LastAffected, "status/last_affected"),
	}
}

func toProductStatusesJSON(st Status) productStatusJSON {

	return productStatusJSON{
		FirstAffected:    toProductIDs(st.FirstAffected),
		FirstFixed:       toProductIDs(st.FirstFixed),
		Fixed:            toProductIDs(st.Fixed),
		KnownAffected:    toProductIDs(st.KnownAffected),
		KnownNotAffected: toProductIDs(st.KnownNotAffected),
		LastAffected:     toProductIDs(st.LastAffected),
		Recommended:      toProductIDs(st.Recommended),
	}
}
