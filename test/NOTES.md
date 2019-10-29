# Key Test File Descriptions

*cvrf-1.2-test-use-everything.xml* - file created to use absolutely everything defined
in the XML schema for CVRF.

*csaf-2.0-test-use-everything.json* - file created from the XML to test the serialization
of everything in the JSON data.

*cvrf-1.2-test-remove-once.xml* - one round of removing elements or attributes
not required by the CVRF schema. This can be used to determine whether the XML
serialization of the optional elements is done correctly. This file removes the
following attributes:

- @CPE
- @VendorID
- @Audience
- @Title
- Threat/@Date

It also removes the following elements:

- ContactDetails
- IssuingAuthority
- Alias
- Generator/Engine and Generator/Date
- Acknowledgment/Name, Acknowledgment/Organization, Acknowledgment/Description,
  Acknowledgment/URL
- Involvement/Description
- Group/Description
- CVE
- CWE
- ProductStatuses
- Vulnerability/Title, Vulnerability/ID, Vulnerability/Notes/Note
- DiscoveryDate
- ReleaseDate
- Threat/ProductID, Threat/GroupID
- TemporalScoreV2
- EnvironmentalScoreV2
- VectorV2
- ScoreSetV2/ProductID
- Entitlement
- Remediation/URL, Remediation/ProductID, Remediation/GroupID
