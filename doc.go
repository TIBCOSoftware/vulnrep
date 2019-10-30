// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright 2019, TIBCO Software Inc. This file is subject to the license
// terms contained in the license file that is distributed with this file.

// Package vulnrep implements an API for working with vulnerability documents.
// Specifically, it implements the Common Vulnerability Reporting Format (CVRF)
// which uses XML serialization, and the Common Security Advisory Framework (CSAF)
// which uses JSON serialization. The home page for the OASIS Common Security
// Advisory Framework Technical Committee
// (https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=csaf)
// has more information about these standards, including schema documents to work
// with these standards.
//
// There is a separate command-line conversion tool (cmd/vulnrepconv in the same
// repository) that invokes the API to convert documents between these two
// formats.
//
// Validation
//
// This package does not rely on available schemas to perform validation of
// documents, but rather explicitly implements the checks in code. This is done
// this way in part because JSON schema does not support the notion of "key" and
// keyref that XML Schema supports. Therefore, for complete validation this code
// needs to implement validation with code.
//
// When a Report has only compliance issues on load or save, the caller API can
// check for the specific *ComplianceErr type, and introspect the contents of
// that error.
//
// Parsing and Serialization
//
// Documents are scanned for errors both when read and written. This
// implementation does not try to be clever about handling large documents, but
// rather assumes that vulnerability reports will not be excessively large.
package vulnrep
