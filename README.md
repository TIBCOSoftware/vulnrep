# vulnrep

Vulnerability Reporting Library implements Go APIs and command line tooling for
parsing and exporting CVRF and CSAF vulnerability report representations.

## Overview

The OASIS [Common Security Advisory Framework](https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=csaf)
Technical Committee specified a XML-based format for sharing information about software
vulnerabilities. OASIS published version 1.2 of that specification - the Common
Vulnerability Reporting Format (CVRF) - on the committee's home
[page](https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=csaf#technical).
That committee also works on a newer JSON format.

This project - the Vulnerability Reporting Library - aims to:

* provide GO APIs to work with vulnerability information
* validate the feasibility and correctness of the new JSON-focused specification
* identify and eliminate issues with mapping to/from the existing XML format
  and the new JSON representation

## Contributing

Before submitting a pull request, please raise an issue to discuss the change.
Pull requests must pass a minimal filter:

* No issues flagged with golangci-lint --enable-all
* Appropriate test cases - if the pull request fixes a bug, then please provide
  a test case demonstrating the bug
* Appropriate comments

### Hints

The enums.go file is generated with the help of the code in cmd/genenums.
Please don't edit this file directly, but instead edit the enums.json file,
then run "go generate".

## License

Note that this project uses [SPDX](https://spdx.org) to annotate source files
with license information.

BSD-3-Clause
