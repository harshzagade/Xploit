# Changelog

## 1.6.0

- Consolidated the final scanner under the Xploit name.
- Added custom `--header` and `--cookie` options for authenticated scans.
- Added exposure checks for sensitive config files, exposed diagnostic endpoints, directory listing, technology headers, sensitive HTML comments, and predictable object identifiers.
- Kept passive mode limited to observed responses/forms and reserved active probes for active/full scans.
- Improved progress reporting, JSON output, CLI option coverage, and regression tests.

## 1.5.0

- Added modular scanner structure and richer report metadata.
- Added scan modes, path scoping, rate limiting, JSON output, and quiet/no-color controls.

## 1.0.0

- Initial CLI scanner release.
- Added bounded same-origin crawling.
- Added checks for SQL Injection, XSS, CSRF, Command Injection, Directory Traversal, Insecure HTTP Headers, Broken Authentication, Sensitive Data Exposure, Open Redirect, and Security Misconfiguration.
- Added detailed terminal output with evidence, impact, remediation, CWE, and validation guidance.
- Added universal `xploit` command support.
