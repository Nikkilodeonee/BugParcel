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

Docker configuration and GitHub Actions are supplied but were not executed in this Windows session. No live user incident data or external service was used. Automatic redaction is still a bounded detector and should be reviewed before sharing real reports.
