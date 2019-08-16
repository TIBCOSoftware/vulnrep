package vulnrep

import "time"

type reportJSON struct {
	Meta            reportMetaJSON      `json:"document"`
	ProductTree     productTreeExp      `json:"product_tree"`
	Vulnerabilities []vulnerabilityJSON `json:"vulnerabilities"`
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
	Distribution      string                `json:"distribution"`
	AggregateSeverity *aggregateSeverityExp `json:"aggregate_severity"`
	References        []referenceExp        `json:"references"`
	Acknowledgments   []acknowledgmentExp   `json:"acknowledgments"`
}

func toReportMetaJSON(meta ReportMeta) reportMetaJSON {

	return reportMetaJSON{
		Title:             meta.Title,
		Type:              meta.Type,
		Publisher:         publisherExp(meta.Publisher),
		Tracking:          toTrackingExp(meta.Tracking),
		Notes:             toNotesXML(meta.Notes),
		Distribution:      meta.Distribution,
		AggregateSeverity: toAggregateSeverityExp(meta.AggregateSeverity),
		References:        toReferenceExps(meta.References),
		Acknowledgments:   toAcknowledgmentExps(meta.Acknowledgments),
	}
}

type vulnerabilityJSON struct {
	Ordinal         int                 `json:"ordinal"`
	Title           string              `json:"title"`
	ID              *vulnIDExp          `json:"id,omitempty"`
	Notes           []noteExp           `json:"notes"`
	DiscoveryDate   time.Time           `json:"discovery_date"`
	ReleaseDate     time.Time           `json:"release_date"`
	Involvements    []involvementExp    `json:"involvements,omitempty"`
	CVE             string              `json:"cve"`
	CWE             *cweExp             `json:"cwe,omitempty"`
	ProductStatus   productStatusJSON   `json:"product_status"`
	Threats         []threatExp         `json:"threats"`
	CVSS            *cvssScoreSetsJSON  `json:"cvss_score_sets,omitempty"`
	Remediations    []remediationExp    `json:"remediations"`
	References      []referenceExp      `json:"references"`
	Acknowledgments []acknowledgmentExp `json:"acknowledgments"`
}

func toVulnerabilityJSON(v Vulnerability) vulnerabilityJSON {
	return vulnerabilityJSON{
		Ordinal:         v.Ordinal,
		Title:           v.Title,
		ID:              toVulnIDExp(v.ID),
		Notes:           toNotesXML(v.Notes),
		DiscoveryDate:   v.DiscoveryDate,
		ReleaseDate:     v.ReleaseDate,
		Involvements:    toInvolvmentExps(v.Involvements),
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
	V2 []scoreSetV3Exp `json:"v2"`
	V3 []scoreSetV3Exp `json:"v3"`
}

func toCVSSScoreSetsJSON(ss *CVSSScoreSets) *cvssScoreSetsJSON {
	if ss == nil {
		return nil
	}
	return &cvssScoreSetsJSON{
		V2: toScoreSetV3Exps(ss.V2),
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
