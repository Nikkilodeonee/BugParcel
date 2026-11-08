# Report and comparison semantics

Tier 3 / app 1.3.0 / incident schema 1.5.

## Timeline and summary

`ReportInsights` derives its model **after redaction**. Summaries reuse sanitized requests, logger names, messages, and stacks; metadata never copies original input or the private review mapping. Timeline references use internal `req-N` / `log-N` IDs, preserving links even when displayed source identifiers are masked.

Only complete dates with explicit UTC offsets enter the timed order. A request event represents its start plus HAR duration, so a failed outcome does not appear before the request has finished. Log events use their recorded time. Ties preserve log file order before request order; untimed events follow the timed events and have no offset. Unknown zones are never assumed. Out-of-range dates/completion times remain untimed. The highlighted first error is the earliest timed ERROR/FATAL/CRITICAL log or failed HTTP/network completion, not a root-cause conclusion.

The brief lists failed requests, the slowest recorded duration, error entries by logger, and the first timed error stack. If no error stack has a usable time, it labels the first stack as file order. Waterfall bars show relative request starts and HAR total durations, not a DNS/connect/TLS phase breakdown. Separate clocks and incomplete captures can make the apparent sequence misleading.

Error grouping hashes the sanitized exception type and stack frame structure, ignoring line numbers and placeholder counters. Python final/chained exception types are included. Logs without stacks group by normalized message, logger, and level. Stack groups are an inspection convenience, not a claim that every instance has the same cause. Grouped views show one representative stack and retain each occurrence's time, source line, and message; full individual entries/stacks remain in JSON. Linked-log views count only group members in that view.

HTML has inline SVG charts and no scripts, fonts, external assets, or network dependencies. Charts split every 24 rows for printing; their preview is limited to 200 requests. HTML/Markdown timeline previews contain at most 1,000 events; full timing/event data remains in JSON. The browser timeline paginates all events in groups of 50. The workspace brief previews 25 failures; the HTML brief previews 50, with complete requests below.

Themes are Paper, Night, and High contrast. The print stylesheet uses a light background, A4 margins, wrapped code, repeated table headings, and avoids splitting each SVG chart. Save PDF through the browser print dialog. Expanded/collapsed disclosure printing can vary by browser; full evidence remains in JSON. [Browser printing CSS](https://developer.mozilla.org/en-US/docs/Web/CSS/Guides/Media_queries/Printing).

## Comparison

Capture a baseline in the workspace and load the later capture, or explicitly select two requests within one incident. The baseline holds original input strings only in browser memory so changing redaction settings can be applied consistently to **both** sides. Clear baseline/session, reload, or closing the page discards it. No saved incident library or persistence is introduced.

The server re-analyzes original inputs rather than accepting a client-authored sanitized model. In incident comparison, the after/current side supplies the privacy options for both sides, including custom values, review choices, policy, profile, decoder, and body inclusion. Stable review choices apply to matching values in either capture. CLI diff accepts common policy/category/custom options, but rejects per-value `--keep`/`--force`; use the workspace to resolve those choices.

Requests pair by uppercase method and normalized scheme/authority/path, excluding query and fragment; repeated routes pair in capture occurrence order. Different hosts/paths/methods become additions/removals. Explicit two-request comparison bypasses route pairing. This may pair different business operations; the UI explains that the comparison is not identifier-based correlation. Encoded path spellings and explicit/default ports can still differ.

Fields compared are method, full sanitized URL, status/text, duration, request/response headers, and included bodies. Request/trace ID headers, Date, Server-Timing, and known provider tracing headers are ignored by default; the switch / `--include-volatile-headers` includes them. Header absence differs from an empty value. Bodies must be included to compare them. Placeholder counters are normalized by category and never treated as stable identities. Changes hidden entirely by redaction are **unknown**, not evidence of equal originals. Error group counts are compared by signature.

Two-request exports contain only the selected requests and their confirmed ID-linked logs. Timestamp guesses and unrelated requests/logs are excluded. Redaction/scan counters and warnings describe the original source scan; the self-check is rerun on each selected evidence slice, and this provenance is stated in the comparison notes.

Field previews are limited to 4,000 characters with an explicit label; full sanitized captures remain in comparison JSON. The browser paginates 20 changed/added/removed requests at a time. Existing file, entry, and field limits still apply. The API's 28 MB total JSON request limit also applies to both comparison captures together; split large incidents before comparing. No original review mapping, original inputs, or policy source is exported.

## Snippets and replay

Per-request output formats: cURL, HTTPie, GitHub issue, Jira wiki markup, Slack, and Markdown. Issue/chat formats are text for the user to copy; BugParcel does not post to those services. Markdown fences grow around imported backticks; Jira/Slack delimiters are neutralized inside the evidence.

Replay produces POSIX shell text only. Literal URL/header/body values are single-quoted with apostrophes escaped; masked fields become checked, double-quoted environment-variable expansions. No original secret is restored. The same placeholder reuses its variable name, but numbers are local to that capture:

```sh
export BP_CREDENTIAL_1='your replacement token'
# URL components require percent-encoding, e.g. a literal @ becomes %40.
export BP_URL_EMAIL_1='person%40example.test'
# Supply the whole serialized body if the template asks for it.
export BP_REQUEST_BODY='{"email":"person@example.test","amount":149.9}'
sh replay.sh
```

Inspect the target and generated command before running it yourself. Header variables contain raw values, while `BP_URL_*` values must be valid percent-encoded URL components. If a URL was invalid or truncated, supply a complete `BP_REQUEST_URL`. Masked, missing, excluded, or truncated bodies require a complete `BP_REQUEST_BODY` rather than interpolating raw secrets into JSON/form syntax. An explicitly empty body variable is allowed.

cURL uses `--globoff`, restricts initial protocols to HTTP/HTTPS, and uses `--data-raw` so an initial `@` in a body cannot read a local file. It does not enable redirect following or disable certificate verification. HTTPie uses `--ignore-stdin` and `--raw`; neither generator executes anything. Transport/compression headers, invalid header names/values, and truncated headers are omitted. Replays use normalized text and may differ from original cookies, binary/multipart bodies, compression, browser state, or signed byte sequences. Existing intentionally kept/allowlisted values can appear, and the template states its source self-check count. [cURL options](https://curl.se/docs/manpage.html), [HTTPie CLI options](https://httpie.io/docs/cli).
