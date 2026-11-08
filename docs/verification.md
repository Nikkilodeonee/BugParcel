# Local verification

Verified on Windows on 7 November 2026.

- `mvn -o verify`: Java behavioral and MockMvc integration tests pass; runnable Spring Boot JAR produced. Built and tested with Java 21, compiled for Java 17.
- `node --check src/main/resources/static/app.js`: passes.
- The packaged application starts successfully with both Microsoft Java 17 and Oracle Java 21 when using the Windows socket compatibility option supplied by the launcher.
- The Windows `start-bugparcel.cmd` launcher starts the packaged application on loopback port 8087.
- The browser sample reports 6 requests, 2 failures, 5 linked requests, 9 server log entries, and 2 unlinked logs.
- Imported the HAR and NDJSON fixture files through the browser's actual file picker. The same incident counts and correlations appear.
- Failed-request filtering returns 2 of 6 requests.
- Disabling email redaction changes the replacement count and displays a warning in the export dialog. Restoring it reapplies the placeholders.
- Including bodies shows the redacted JSON request and response preview. Adding `order-1842` as a custom value replaces it in URLs and logs.
- Downloaded a standalone HTML report through the interface; API tests also verify HTML, Markdown, and JSON exports do not contain the fixture credentials, email, cookie value, or IPv4 address.
- Clear session removes the rendered request evidence, custom-value chips, and title value as well as the source state.
- Checked the desktop layout at 1440 px and mobile layout at 390 px. No horizontal document overflow at the mobile breakpoint. Temporary viewport overrides were reset.
- The browser console has no captured errors or warnings during the checked workflow.

Screenshots: [desktop](workspace.jpg), [mobile](mobile.jpg).

## Redaction review update

- The initial value-review update passed 32 tests (16 incident-service cases, 10 redaction-policy cases, and 6 API integration cases).
- Added regression coverage for short/common credentials, numeric and boolean JSON values, exact sensitive-key boundaries, contextual version preservation, automatic token boundaries, and short URL credentials.
- Added coverage for stable per-value exclusions, overlapping rules, displayed-ID redaction with intact links, IPv6 literals, and labeled phone numbers. HTML, Markdown, and JSON exports honor exclusions and omit the original-value review list and IDs.
- Checked the new review screen in the browser: reveal originals, expand locations, keep a value, reset choices, search findings, and see the export notice for kept values.
- Keeping the fixture email changes the redacted count from 10 to 7 while leaving its category enabled; resetting restores 10.
- Confirmed that clearing a session removes review originals from the rendered DOM. Checked the updated review layout at 390 px with no horizontal document overflow; the table scrolls inside its own container.
- No captured browser console errors or warnings. Temporary viewport overrides were reset.

Review screenshot: [detected values](redaction-review.jpg).

## Ambiguity and date regression update

- Final automated result: **42 tests passed** (16 incident-service cases, 19 redaction-policy cases, and 7 API integration cases).
- Reproduced the reported build/release IP leak, missing version-only findings, bare `::` replacement, numeric eight-group ambiguity, and `tel=` timestamp truncation before applying fixes.
- Explicit version keys require structured fields or `:`/`=` in text. Build/release prose no longer suppresses address detection. Version-context matches remain listed with ambiguity metadata.
- Bare `::` and `:` are ignored. Unlabeled eight-group decimal sequences remain visible as ambiguous findings; address fields, address labels, and brackets enable automatic redaction.
- Date-like phone spans are rejected. Regression coverage also retains contiguous, international, and parenthesized phone formats.
- Forced redaction and Keep choices are tested across HTML, Markdown, and JSON exports, with review IDs excluded from reports. Mixed-context values and Keep precedence are covered.
- Imported the synthetic [HAR](../src/test/resources/samples/ambiguity.har) and [logs](../src/test/resources/samples/ambiguity.ndjson) through the browser's file pickers. The workspace showed five address candidates, two ambiguous values, and three automatic substitutions.
- Browser-verified Automatic → Redact all occurrences → Keep value choices, Reset, ambiguity reasons, and the export notice. Forcing the version value increased substitutions from three to five; Reset restored three and the automatic ambiguity notice.
- Checked 1200 px desktop and 390 px mobile containment. No captured console errors/warnings; viewport overrides were reset.
- Documented the underscore/hyphen boundary trade-off for secrets joined to prefixes.

Screenshot: [ambiguity review](ambiguity-review.jpg).

## Tier 1 correlation release (1.1.0)

- **91 tests passed on Microsoft Java 17.0.20.1** using `mvn -o verify`: 35 Tier 1 correlation cases, 16 incident-service cases, 19 redaction-policy cases, 8 API integration cases, and 13 CLI cases.
- Provider fixtures cover AWS Root vs Self, Cloudflare suffix changes and namespace separation, Google's unsigned decimal span bound, Azure exact IDs vs hierarchical root context, and Sentry/W3C interoperability. Invalid/zero values and stronger-ID precedence are covered.
- Format fixtures cover Spring Boot, Logback/Log4j2 clock-only and full-date patterns, Python default/common patterns, quoted logfmt, Apache/nginx combined access, Docker-wrapped text/JSON, mixed sources, and Java/Python multiline stacks. Quoted message examples cannot invent logfmt ID fields.
- Diagnostics distinguish missing HAR IDs, absent logs, missing log IDs, incompatible types, and different values. API tests verify detected formats and diagnostics reach exports.
- Hints default off in API, Java constructors, UI, and CLI. Tests verify the ±2-second boundary, three-nearest limit, explicit-offset requirement, conflicting IDs, and unchanged confirmed/unlinked counts. All exports use redacted evidence.
- Browser-imported [synthetic HAR](../src/test/resources/samples/correlation.har) and [mixed logs](../src/test/resources/samples/correlation.log). Confirmed 1 request, 4 log entries, 4 detected formats, both missing-ID diagnostics, and 0 confirmed links.
- Enabling time hints displayed 100/200/300 ms guesses; the entry with only a local clock was excluded. The confirmed link count stayed 0 and the email remained redacted.
- Checked all four setup-guide selections. Express **Copy snippet** displayed its success status. Snippets are generated into README from the same module used by the UI.
- Downloaded HTML through the UI and inspected the actual downloaded file: unconfirmed labels and hint distances present, synthetic email absent. The CLI/API integration cases cover the other report formats.
- Checked the 469 px narrow layout (no horizontal document overflow) and 1366 px desktop layout; reset the temporary viewport override. The file chooser was slow in automation but both imports completed successfully.
- Windows launcher started the packaged 1.1.0 JAR on loopback successfully. Stopped the owned preview server after verification.

Screenshots: [correlation workspace](tier-1-workspace.png), [narrow setup guide](tier-1-mobile.png).

Time hints remain guesses. Custom logging patterns outside the documented shapes can remain unstructured. Example middleware has documented async/streaming integration limits; the Express/Django/nginx snippets were inspected against primary API references but were not deployed into separate framework applications here.

## Tier 2 redaction release (1.2.0)

- Final Java 17 result: **130 tests passed**, including two jqwik properties exercising **350 generated cases**. Provider secrets and encoded containers are checked across HTML/Markdown/JSON; custom values inside IDs retain confirmed links.
- Regression corpus: **77 gated cases** (35 must-not-redact, 20 adversarial), 43 expected redactions, 0 false positives, 0 misses, plus 2 listed known limitations, **on these hand-written fixtures only**. Tests generate `target/redaction-corpus-metrics.json` with per-category numbers; CI is configured to gate the cases and publish a per-category summary/artifact. Recorded metrics: [JSON](corpus-metrics.json).
- Review follow-up: the adversarial cases exposed and fixed (1) a card followed by a date being missed because the whole digit run was checked at once, (2) URL paths, `sha256-` integrity hashes and `WORD_WORD_123` constants flagged by the entropy detector, and (3) `Chrome/118.0.0.0` in a User-Agent being redacted as an IPv4 address. Final result: **133 tests passed**. `node --check` and the CI summary script were not run locally (Node is not installed on this machine).
- Regression coverage includes AWS/GitHub/Stripe/Slack tokens, signed and unsigned JWT shapes, complete/incomplete private-key blocks, multiple HTTP/database URL credentials, Luhn cards, IBAN country length/MOD-97, PESEL date/checksum, and entropy suspects. Invalid checksums/dates, separators, versions, and key boundaries remain covered.
- Decoder tests cover base64 adjacent to `=`, nested base64, JWT claims, custom values inside encoded text, base64/gzip HAR bodies, decoding off, excessive depth, and compressed bombs. Oversized/invalid binary HAR content is omitted with explicit notes.
- Policy tests cover defaults/overrides, automatic CLI discovery, explicit paths, opt-out, field-scoped rules, exceptions that cannot spread across fields, invalid regexes/keys/tags/aliases, and UTF-8 byte limits. Regexes use RE2/J. Policy content is excluded from exports.
- Self-check tests cover disabled/allowlisted matches, unexpected boundary-joined credentials, no original values or review IDs in check metadata, and strict exit codes. Source values that resemble generated placeholders cannot bypass redaction.
- Browser-checked **Security sample**: Standard masks known tokens/keys and encoded email; Paranoid also masks card/IBAN/PESEL/entropy examples. The example policy hides TEAM-ALPHA, intentionally retains the synthetic public contact, and changes the scoped self-check to 1 remaining match.
- Browser-checked body inclusion: decoded response JSON contains a redacted email and no base64 container; request API key/payload are masked. Decoder off displays **Limited check**. Clearing a policy restores standard/on defaults; reapplying honors policy defaults.
- Review rows show detector reasons, decoded locations, and policy-allowlisted status. Export dialog carries the scoped self-check warning. Downloaded the actual HTML and inspected it: only the intentional public contact remains; token/card/IBAN/PESEL/private-key originals and policy content are absent.
- Clear session removes rendered originals and policy status and resets the profile; checked the DOM no longer contains the demo's original private email. Browser captured no warnings/errors. Checked 469 px containment and 1366 px desktop; viewport override reset.
- Stopped the owned local preview server after verification. The release ZIP includes the example YAML policy and updated CLI instructions.

Screenshots: [Tier 2 workspace](tier-2-workspace.png), [narrow policy controls](tier-2-mobile.png). Detector/policy/decoder/self-check limits and references: [redaction guide](redaction.md).

No detector or zero-match badge guarantees that all sensitive information is gone. Paranoid mode can flag harmless tokens. Unsupported encodings, unknown embedded secrets, omitted/truncated evidence, and shared detector blind spots remain review limits. The recorded counts above come from local Java 17 verification; GitHub workflow outcomes are tracked in Actions. No live incident or real provider credential was used.

## Tier 3 reports release (1.3.0)

- **151 tests passed on Microsoft Java 17.0.20.1** with `mvn -o -q verify`, including two jqwik properties with **350 generated cases**. This adds 18 report, replay, comparison, API, and CLI cases to the previous 133. A stale `TmpProbeTest` XML from an earlier local probe was excluded from the count; it is not in the source or current run.
- The 77-case redaction corpus remains green: TP 43, FP 0, FN 0, with its 2 documented known limitations. Ran the per-category summary script locally. The bundled Node runtime now permits syntax checks: `node --check` passes for `app.js`, `reports.js`, and `request-id-guides.js`. CI's check script covers all three modules.
- Regression coverage checks completion-time chronology, unknown zones, stable ties, unrepresentable dates/durations, finite SVG coordinates, escaped imported markup, logger summaries, Java/Python stack grouping, and a 400-error group that retains every entry.
- Comparisons are checked for current privacy settings on both captures, unknown masked values and placeholder numbering, repeated endpoint order, added/removed requests, query/status/body changes, absent versus empty headers, volatile-header options, bounded previews, and scoped request/log exports. Snippet tests cover all six formats, apostrophe/shell quoting, required replacement variables, whole-body variables, invalid methods/URLs/headers, local-file-like bodies, and hostile Markdown/Jira/Slack delimiters.
- Browser-checked the merged timeline, first-error lead-up filter, waterfall labels, two-request comparison, request copying, export theme controls, and the synthetic before/after example. The demo shows **3 changed / 3 unchanged requests, failures 2 → 0, errors 1 → 0, payment duration 3048 → 220 ms**. Including bodies survives the demo capture switch and shows the three changed response bodies.
- Imported a synthetic 400-entry log fixture through the file chooser: one collapsed group contains all 400 occurrences. Turning grouping off renders all 400 cards, then folds them again. Capturing a baseline and clearing the session removes old evidence from the DOM and empties both comparison selectors.
- Downloaded the actual Night-theme incident HTML and comparison HTML through the interface. Source inspection confirms script-free escaped output, inline SVG in the incident report, theme/print CSS, and no fixture token, private email, cookie, or IPv4 originals. Local-file navigation is blocked by the in-app browser policy, so downloaded HTML/PDF rendering was **not** verified there; no PDF was generated. The workspace itself was visually checked at 1440 px and 390 px, with no page overflow. Viewport override reset; no browser console warnings/errors were captured.
- Created `artifacts/BugParcel-1.3.0.zip` with launchers, JAR, example policy, license, and updated instructions. The packaged JAR passes Java 17 `version`, strict incident diff, and strict cURL/HTTPie export smoke checks. Both generated replay scripts pass Git Bash `-n` syntax checks; no generated network request was executed. SHA-256 is recorded in `artifacts/SHA256SUMS.txt`.
- Stopped the owned local preview server after verification.

Screenshots: [timeline and brief](tier-3-workspace.png), [comparison with bodies](tier-3-comparison.png), [390 px comparison](tier-3-mobile.png). Detailed behavior and limits: [reports guide](reports.md).

## Tier 4 input release (1.4.0)

- **180 tests passed on Microsoft Java 17.0.20.1** with `mvn -o -q verify`, zero failures/errors/skips. This adds 29 executions to Tier 3. The two existing jqwik properties still cover **350 generated cases**, and the 77-case redaction corpus remains TP 43 / FP 0 / FN 0 with its two documented limitations. Counts exclude the stale probe XML described above.
- Capture tests cover HAR, Charles XML, mitmproxy format-21 HTTP flows, detailed Newman JSON, Postman run summaries, and Playwright trace ZIPs. Every format is checked through the same redaction and HTML/Markdown/JSON export boundary. Detailed inputs preserve the fixture's five confirmed links; summary-only Postman lacks the ID headers and correctly reports zero links.
- Archive tests cover gzip, UTF-16 logs, mixed arrays/text, path traversal and absolute/drive names, nested ZIPs, missing and unsafe body references, corrupt gzip, expansion limits, repeated-resource memory multiplication, and bounded XML depth/entity behavior. Playwright's missing response status becomes a network failure; unavailable duration gets an approximation note.
- Directory/glob tests run on Windows, checking sorting/deduplication, nested and zero-directory `**` combinations, and empty matches. CLI tests exercise all source samples, archived logs, file-URL pulls, option conflicts, and exclusion of URL/settings/original fixture secrets from reports.
- Pull-client tests use synthetic loopback HTTP services only. They check Loki literal-ID quoting and timestamps/ID parsing, Elasticsearch JSON term filters and partial results, authorization headers, no redirect following, no error-body echo, unsupported URLs, missing IDs, result caps, streaming byte-budget cancellation, and a deadline that includes a stalled response body. They do not establish compatibility with a particular real deployment's credentials, tenants, or index mappings.
- Browser-checked **Supported inputs & capture recipes**, the trace + archived-log demo, included body redaction, actual JSON download, and direct Charles XML file-picker import. The trace demo shows **6 requests / 2 failed / 5 linked / 9 logs**, with one capture stream and two log files. Comparing its encoded trace against the original plain HAR gives **6 unchanged requests**, confirming transport settings survive baseline capture/re-analysis.
- Inspected the actual downloaded JSON: schema 1.6, correct source counts, included bodies, no fixture token/email/cookie/IP originals, and no original capture, encoding options, policy source, or review map. Clear session empties source metadata and baseline selectors. Checked 1440 px and 390 px layouts, including the scrollable input guide, with no page overflow or browser console warnings/errors. Viewport override reset.
- JavaScript syntax checks pass for `app.js`, `reports.js`, `request-id-guides.js`, and the synthetic-fixture generator. Pipeline recipes and input semantics were checked against the primary references linked in the [input guide](inputs.md); Docker/kubectl/journalctl were not run against live services here.
- Created `artifacts/BugParcel-1.4.0.zip`, verified its SHA-256 against `artifacts/SHA256SUMS.txt`, and smoke-tested the **packaged JAR on Java 17**: version, `sample --inputs`, strict reports for all six capture formats with ZIP logs, and explicit local file-URL pulling. Packaged outputs retain all six requests/nine logs and exclude the fixture secrets.
- Stopped the owned loopback preview on port 8088 after verification. No live incident or real service credential was used.

Screenshots: [input workspace](tier-4-workspace.png), [390 px workspace](tier-4-mobile.png), [input guide](tier-4-guide.png). Format fidelity, transport, retrieval, and resource limits: [input documentation](inputs.md).
