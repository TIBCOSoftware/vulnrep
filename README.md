# vulnrep

Vulnerability Reporting Library implements Go APIs and command line tooling for
parsing and exporting CVRF and CSAF vulnerability report representations.

## Overview

At OASIS, the
[Common Security Advisory Framework](https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=csaf)
Technical Committee specified a format for sharing information about software
vulnerabilities via XML. Version 1.2 of the Common Vulnerability Reporting
Format (CVRF) can be found on the technical committee's home
[page](https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=csaf#technical).

The Vulnerability Reporting Library exists to implement and validate the
subsequent version of the specification based on JSON serialization. This
implementation aims to either identify or eliminate issues with mapping to/from
the existing XML format and the new JSON representation.

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
