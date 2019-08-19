# vulnrep

Implements APIs and tooling for capturing and converting CVRF and CSAF
vulnerability report representations.

## Overview

At OASIS, the Technical Committee called the
[Common Security Advisory Framework](https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=csaf)
defined a specification for sharing information about software vulnerabilities
via XML. Version 1.2 of the Common Vulnerability Reporting Format (CVRF) can
be found on that [page](https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=csaf#technical).

In producing the subsequent version of the specification (implemented in JSON),
this tool was created both to implement the specification, and eliminate
issues with mapping to / from each format.

## Contributing

Before submitting a pull request, please raise an issue to discuss the change.
Pull requests must pass a minimal filter:

* No issues flagged with golangci-lint --enable-all
* Appropriate test cases - if the pull request fixes a bug, then please provide
  a test case demonstrating the bug
* Appropriate comments

## License

Note that this project uses [SPDX](https://spdx.org) to annotate source files
with license information.

BSD-3-Clause
