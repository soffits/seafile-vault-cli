# Security Policy

Report vulnerabilities privately through the repository security advisory flow or by opening a minimal issue that does not disclose exploit details.

Do not include real Seafile hosts, origin IPs, repo IDs, repo tokens, token-bearing upload links, library names, or private paths in public reports.

Local-path uploads reject final symlinks, require a regular file, check configured size limits before requesting an upload link, and upload from the same descriptor that was validated. Direct-origin upload keeps token-bearing upload URLs out of argv and fails closed when descriptor-safe curl input is unavailable.

Supported versions follow the latest released version until a formal release policy is published.
