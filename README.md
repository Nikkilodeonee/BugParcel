# BugParcel

**Connect browser requests to backend logs. Share the evidence.**

When a checkout fails, the useful evidence often lives in two places: a HAR recording from the browser and a server log file. BugParcel connects matching identifiers, lets you review redactions, and packages the result as a report someone can open without installing anything.

A local Java 17 / Spring Boot application with a dependency-free browser interface. No account, database, analytics, AI service, or cloud upload.

![BugParcel incident workspace](docs/workspace.jpg)

## Try it

Requires **Java 17+** to run the packaged app. Building from source also requires **Maven 3.9+**.

```sh
mvn verify
java -jar target/bugparcel-1.2.0.jar
```

Open **http://127.0.0.1:8087** and click **Open the sample incident**. Or open http://127.0.0.1:8087/?sample=1 to jump directly into the demo.

On Windows, double-click `start-bugparcel.cmd`. It uses the built JAR when available and builds it otherwise. To rebuild after changes:

```powershell
.\scripts\run.ps1 -Build
```

Use another port with `--server.port=8090`, `BUGPARCEL_PORT=8090`, or `scripts/run.ps1 -Port 8090`.

The Windows launchers also use a process-local Java socket-directory option to avoid a JDK selector-pipe failure with some Windows temporary paths. The JDK falls back to a TCP pipe; no Windows security settings or global environment variables are changed. See the [OpenJDK pipe implementation](https://github.com/openjdk/jdk21u/blob/master/src/java.base/windows/classes/sun/nio/ch/PipeImpl.java).

After a successful build, create a portable ZIP with `scripts/package.ps1`. It contains the runnable JAR, Windows launcher, instructions, and license. Java 17+ is the only runtime prerequisite.

## Command line

The same JAR is also a CLI. Commands never start a server or open a port, and the report starts in well under a second.

```sh
java -jar target/bugparcel-1.2.0.jar sample                      # writes ./bugparcel-sample/
java -jar target/bugparcel-1.2.0.jar report checkout.har --logs app.log -o report.html
java -jar target/bugparcel-1.2.0.jar review checkout.har --logs app.log
```

The portable ZIP adds `bugparcel.cmd` and `bugparcel` launchers, so these become `bugparcel report ...`.

```sh
# Pipe logs in, write Markdown to stdout (the summary goes to stderr)
kubectl logs deploy/api | bugparcel report checkout.har --logs - -o - --format md > incident.md

# Several log files, mixed formats; also redact an exact value
bugparcel report checkout.har --logs api.log --logs worker.ndjson --redact "Acme Corp" -o report.html

# See what was detected (originals hidden unless --reveal), then decide
bugparcel review checkout.har --logs app.log
bugparcel report checkout.har --logs app.log --keep 056e8dd9 --force 9a31c0de --strict
```

| Command | Purpose |
| --- | --- |
| `report <file.har>` | Correlate, redact, and write HTML (default), Markdown, or JSON. The format follows the `-o` extension or `--format`. |
| `review <file.har>` | List each detected value with category, uses, and status. `--json` for tooling. Use any unique 8+ character ID prefix with `--keep` or `--force`. |
| `sample` | Write the fictional checkout incident to try it. |
| `serve [--port N]` | Start the web interface (also the default with no command). |

Exit codes are `0` success, `1` failure (unreadable file, invalid input), `2` usage error, and `3` when `--strict` finds ambiguous address values that automatic rules kept visible, which makes it usable as a CI gate. Error messages never echo input content. Logs may be UTF-8 or UTF-16 (what PowerShell 5 `>` writes); `--logs -` reads standard input. Run `bugparcel help report` for every option.

The CLI uses the identical analysis and redaction code as the web interface, so the same limits and caveats apply. Redaction is still pattern-based: run `review` before sharing a report.

## The sample incident

A synthetic shop checkout has six browser requests and nine server log entries:

- A product request and cart update succeed.
- An expired coupon returns `422`.
- A payment request returns `500`; its shared request ID links three log entries, including a database connection timeout.
- An order poll shares the payment trace, so it is labeled as shared trace context.
- A shipping request has no matching identifier. Two unrelated log entries remain unlinked.

Expected results: **6 requests · 2 failed · 5 linked · 9 logs · 2 unlinked logs**. The data is fictional, including all credentials and contact details. Download the files from **Sample files** in the header to try importing them yourself.

## What works

- Import HAR recordings and automatically detect JSON, Spring Boot, Logback/Log4j2, Python, logfmt, Apache/nginx access, and Docker JSON logs, including mixed files and multiline stacks.
- Inspect HTTP status, duration, headers, optional text bodies, correlation IDs, and linked logs.
- Filter failed or unlinked requests; search requests and logs; jump from a log entry to its request.
- Match typed request/edge IDs before broader correlation/trace IDs. Repeated IDs are labeled as shared context. Optional time hints are unconfirmed guesses and never become ID links.
- Replace credentials, cookies, known sensitive fields, email addresses, IPv4/IPv6 literals, and explicitly labeled phone numbers with consistent placeholders.
- Add exact custom values for customer names, internal hostnames, or other data that automatic detection does not cover.
- Turn redaction categories on or off and preview the resulting evidence. Bodies are excluded by default.
- Review every detected value with its categories, source locations, and substitution count. Choose **Automatic**, **Redact all occurrences**, or **Keep value**. Ambiguous address-like values remain listed even when automatic rules leave them visible. Search and pagination cover the full detected list.
- Export standalone HTML, Markdown, or normalized JSON. Export always re-analyzes the original in-memory input with the current settings.
- Keyboard-accessible controls, responsive layouts, visible focus states, a `/` shortcut for request search, and light and dark themes that follow your system setting.

![Local detected-value review](docs/redaction-review.jpg)

## Import your own incident

1. In Chrome DevTools, open **Network**, clear previous traffic, and reproduce the problem. Export a HAR recording. A short recording is easiest to investigate.
2. Add server logs from the same incident. JSON logs give the most reliable field extraction.
3. Select a failed request. Inspect the linked entries and stack traces. Shared trace context is broader than a single request.
4. Open **Redactions**, review the defaults and the detected-value list, and add exact custom values where needed. Choose **Keep value** for a false positive, or **Redact all occurrences** for an ambiguous value that is an address. **Automatic** restores the context policy. Category switches still apply; another overlapping rule can hide a kept value.
5. Inspect the evidence, then download a report. Everything is held in memory; reload or clear the session to discard it.

### Supported identifiers

| Browser headers | Server log fields |
| --- | --- |
| `x-request-id`, `request-id` | `requestId`, `request_id`, `request.id`, nested `request.id` |
| `x-correlation-id`, `correlation-id` | `correlationId`, `correlation_id`, `correlation.id` |
| W3C `traceparent`, `x-b3-traceid`, B3 single header | `traceId`, `trace_id`, `trace.id`, nested `trace.id`, `traceparent` |
| AWS `X-Amzn-Trace-Id` | `X-Amzn-Trace-Id` (Root field), `awsTraceId`, `aws_trace_id`, AWS-shaped `traceId` |
| Cloudflare `cf-ray` | `cf-ray`, `cf_ray`, `cfRay` |
| Google `X-Cloud-Trace-Context` | `traceId` / `trace_id`, `X-Cloud-Trace-Context`, `logging.googleapis.com/trace` |
| Azure `Request-Id` | Exact `requestId` / `Request-Id`, or hierarchical root in `operation_Id`, `operation.id`, `azureRootId` |
| Sentry `sentry-trace` | `sentry-trace`, `traceId` / `trace_id`, compatible W3C `traceparent` |

Headers can come from the request or response. JSON fields are recognized at the top level and in `mdc`, `context`, `labels`, and `headers`. Trace IDs must be 16 or 32 hexadecimal characters and cannot be all zeros. W3C version-00 traceparents require the standard length and a nonzero parent ID. Google decimal span IDs must fit an unsigned 64-bit integer; Sentry span IDs must be nonzero.

AWS joins use the validated Root value, never Self. Cloudflare joins use the 16-hex Ray value without its datacenter suffix (the suffix can change along the route); Ray IDs are not guaranteed globally unique. Azure exact Request-Id matches take precedence over hierarchical root context. Hierarchical roots remain a separate namespace from W3C trace IDs. Trace/root matches can describe an entire distributed operation. The priority is requestId → cfRay → correlationId → traceId → awsTraceId → azureRootId; the first matching type wins, without widening to weaker matches.

Recognized text logs extract explicit supported `key=value` or `key:value` fields (including quoted values). Keys embedded in quoted logfmt messages are not interpreted as actual ID fields. JSON messages are not searched for invented structured fields.

Provider references: [AWS](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-request-tracing.html), [Cloudflare headers](https://developers.cloudflare.com/fundamentals/reference/http-headers/), [Ray ID limitations](https://developers.cloudflare.com/fundamentals/reference/cloudflare-ray-id/), [Google](https://docs.cloud.google.com/trace/docs/trace-context), [Azure/.NET](https://learn.microsoft.com/en-us/dotnet/core/diagnostics/distributed-tracing-concepts), [Sentry SDK](https://github.com/getsentry/sentry-go/blob/master/tracing.go).

### Detected log formats

Detection runs per entry. The workspace, CLI summary, and reports show all detected formats and entry counts. Stack continuations do not count as new entries. Logback and Log4j2 share a format label because their common default shapes cannot identify the originating library reliably.

| Detected format | Example shape |
| --- | --- |
| JSON | NDJSON or an array of objects; dotted/nested ECS fields supported |
| Spring Boot text | `2026-11-07T14:32:08Z ERROR 33 --- [main] api.Service : Failed requestId=pay-42` |
| Logback / Log4j2 text | `14:32:08.123 [main] ERROR api.Service - Failed requestId=pay-42` (full date also accepted) |
| Python logging | `ERROR:api:Failed request_id=pay-42` or `2026-11-07 14:32:08,123 - api - ERROR - Failed request_id=pay-42` |
| Timestamp + level text | `2026-11-07T14:32:08Z ERROR requestId=pay-42 Failed` |
| logfmt | `time=2026-11-07T14:32:08Z level=error request_id=pay-42 msg="Payment failed"` |
| Apache / nginx access | Common/combined format; an optional explicit `request_id=...` field can link it |
| Docker JSON | `{"log":"...\n","stream":"stderr","time":"2026-11-07T14:32:08Z"}`; unwraps text/JSON and uses envelope time |
| Unstructured text | Retained with a visible warning; no IDs inferred |

These are supported shapes, not every possible custom logging pattern. Default access logs often have no ID; install the nginx snippet below. Time-only Java defaults and Python logs without an offset can still link by ID, but cannot produce time hints. No date or timezone is invented. ANSI color sequences are stripped from text logs. Malformed JSON lines are skipped with a count, never silently reinterpreted as another format.

### When nothing links

The workspace explains whether the HAR has no usable ID headers, logs are absent, logs have no usable ID fields, identifier types do not overlap, or compatible types have different values. It links directly to the setup guide. Diagnostics contain field types and guidance, never original identifier values. Fixing instrumentation only helps **new** HAR/log captures.

### Optional time hints

The **Show time hints** checkbox and CLI `--timestamp-hints` flag are **off by default**. They suggest up to three unlinked log entries within ±2 seconds of each unlinked request's start, ordered by distance. A complete date and explicit UTC offset are required on both sides. Logs with contradictory known IDs or existing confirmed links are excluded. Clock skew, concurrency, and reused timestamps can mislead.

Hints are labeled **unconfirmed guesses** in the UI, HTML, and Markdown, and stored separately in JSON `incident.correlation.timestampHints`. They do not change `logIds`, `matchKind`, confirmed-link counts, or unlinked counts. There is a 5,000-hint incident limit and a 200-candidate per-request limit for dense windows; reaching a limit produces a warning. Hints reference already redacted evidence only.

### Add request IDs

Return `X-Request-ID` to the browser and include the **same** ID in server logs. Choose the relevant snippet below, or open **How it works → Add request IDs** in the UI and copy it there. The snippets are kept in sync by `node scripts/update-guides.mjs`.

IDs are diagnostic labels, never credentials. Validate incoming values or generate them at a trusted edge. Preserve the ID through proxies/downstream calls; for cross-origin browser JavaScript that reads it, expose `X-Request-ID` through CORS. Record a new HAR and matching logs after installation. Check the response header and log field contain identical values before importing.

<!-- request-id-guides:start -->

### Spring Boot

Spring Boot 3+, synchronous Servlet MVC. Put this class in a scanned package and the logging property in application.properties. For @Async, reactive work, or worker pools, use Micrometer Tracing/context propagation; MDC is thread-local.

```java
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.UUID;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class RequestIdFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request,
            HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String incoming = request.getHeader("X-Request-ID");
        String id = incoming != null && incoming.matches("[A-Za-z0-9._-]{1,128}")
            ? incoming : UUID.randomUUID().toString();
        String previous = MDC.get("requestId");
        MDC.put("requestId", id);
        response.setHeader("X-Request-ID", id);
        try {
            chain.doFilter(request, response);
        } finally {
            if (previous == null) MDC.remove("requestId");
            else MDC.put("requestId", previous);
        }
    }
}

// application.properties (separate file):
// logging.pattern.console=%d{yyyy-MM-dd'T'HH:mm:ss.SSSXXX} %-5level %logger{36} requestId=%X{requestId} %msg%n
```

[API reference](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/web/filter/OncePerRequestFilter.html)

### Express

Node 18+, Express 4/5, ES modules. Install this middleware before routes. Call log() inside request work so async operations inherit the ID. The finish event writes the same ID explicitly.

```javascript
import express from 'express';
import { randomUUID } from 'node:crypto';
import { AsyncLocalStorage } from 'node:async_hooks';

const app = express();
const context = new AsyncLocalStorage();
function log(level, message) {
  console.log(JSON.stringify({ timestamp: new Date().toISOString(),
    level, message, requestId: context.getStore()?.requestId }));
}
app.use((req, res, next) => {
  const incoming = req.get('X-Request-ID');
  const requestId = /^[A-Za-z0-9._-]{1,128}$/.test(incoming ?? '')
    ? incoming : randomUUID();
  res.setHeader('X-Request-ID', requestId);
  res.on('finish', () => console.log(JSON.stringify({
    timestamp: new Date().toISOString(), level: 'INFO',
    message: 'HTTP ' + res.statusCode, requestId
  })));
  context.run({ requestId }, next);
});
app.get('/example', (req, res) => {
  log('INFO', 'Example requested');
  res.json({ ok: true });
});
app.listen(3000);
```

[API reference](https://nodejs.org/api/async_context.html#class-asynclocalstorage)

### Django

Save as myapp/request_ids.py. Add myapp.request_ids.RequestIdMiddleware near the start of MIDDLEWARE. The sync middleware also works through Django’s ASGI adaptation; streaming iterators and background tasks need explicit context propagation. Merge the shown handler/filter configuration into your existing LOGGING setting.

```python
import logging
import re
import time
from contextvars import ContextVar
from uuid import uuid4

request_id = ContextVar("request_id", default="-")

class RequestIdFilter(logging.Filter):
    def filter(self, record):
        record.request_id = request_id.get()
        return True

class UtcFormatter(logging.Formatter):
    converter = time.gmtime

class RequestIdMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        incoming = request.headers.get("X-Request-ID", "")
        value = incoming if re.fullmatch(r"[A-Za-z0-9._-]{1,128}", incoming) else str(uuid4())
        token = request_id.set(value)
        try:
            response = self.get_response(request)
            response["X-Request-ID"] = value
            logging.getLogger("myapp").info("HTTP %s", response.status_code)
            return response
        finally:
            request_id.reset(token)

# settings.py (separate file):
LOGGING = {
    "version": 1, "disable_existing_loggers": False,
    "filters": {"request_id": {"()": "myapp.request_ids.RequestIdFilter"}},
    "formatters": {"request": {
        "()": "myapp.request_ids.UtcFormatter",
        "format": "%(asctime)sZ %(levelname)s %(name)s request_id=%(request_id)s %(message)s",
        "datefmt": "%Y-%m-%dT%H:%M:%S",
    }},
    "handlers": {"console": {"class": "logging.StreamHandler",
        "filters": ["request_id"], "formatter": "request"}},
    "root": {"handlers": ["console"], "level": "INFO"},
}
```

[API reference](https://docs.djangoproject.com/en/5.2/topics/http/middleware/)

### nginx

Put log_format in http {}, and the remaining directives in the server/location that proxies your application. Check inherited add_header directives when merging. Use the generated edge ID consistently; the backend should preserve X-Request-ID and log it too.

```nginx
# Inside http {}:
log_format bugparcel escape=json
    '{"timestamp":"$time_iso8601","level":"INFO",'
    '"request_id":"$request_id","message":"$request",'
    '"status":$status,"duration":$request_time}';

# Inside your server {} or proxying location {}:
access_log /var/log/nginx/bugparcel.log bugparcel;
proxy_set_header X-Request-ID $request_id;
proxy_hide_header X-Request-ID;
add_header X-Request-ID $request_id always;
# Keep your existing proxy_pass directive.
```

[API reference](https://nginx.org/en/docs/http/ngx_http_log_module.html#log_format)

<!-- request-id-guides:end -->

### Example structured log

```json
{"@timestamp":"2026-11-07T14:32:11Z","level":"ERROR","logger_name":"dev.shop.CheckoutService","message":"Database connection timed out","mdc":{"requestId":"pay-005","traceId":"4bf92f3577b34da6a3ce929d0e0e4736"}}
```

The browser request must contain the same ID for correlation to work. BugParcel does not retroactively add IDs to logs or infer a root cause from an error message.

## Redaction profiles and team policy

Standard now detects AWS/GitHub/Stripe/Slack tokens, JWTs, private-key blocks, URL credentials, and the existing PII patterns. **Paranoid** adds high-entropy suspects, Luhn-checked card numbers, IBANs, and PESEL IDs. Select the profile above the workspace, or use `--paranoid` in the CLI. The **Security sample** demonstrates the new detectors using synthetic data.

Bounded base64/JWT-claims/gzip inspection defaults on. Sensitive encoded containers become placeholders; supported encoded HAR text bodies are decoded and scanned when bodies are included. The export self-check rescans included evidence, flags remaining matches and incomplete checks, and reports intentional exceptions. **It is a second opinion, not a guarantee:** it reuses the same detectors, so it shares their blind spots. A zero count is scoped to known patterns and the selected profile, and you should still read the report before sharing it.

The CLI auto-loads `./bugparcel.yml`; the UI lets you import it under Redactions. Example:

```yaml
version: 1
defaultProfile: paranoid
decodeContent: true
rules:
  - id: customer-reference
    pattern: 'CUST-[0-9]{6}'
    fields: ['* request body/customerId']
allowlists:
  - values: ['public@example.test']
    fields: ['log-* message']
```

```text
bugparcel report checkout.har --logs app.log --paranoid --strict -o report.html
bugparcel report checkout.har --logs app.log --policy team.yml -o report.html
bugparcel review checkout.har --logs app.log --no-policy --no-decode
```

Policy regexes use RE2/J, with bounded safe YAML and field-scoped exceptions. [Full policy schema, detector references, decoder limits, precedence, and self-check scope](docs/redaction.md). [Example policy](src/main/resources/samples/bugparcel.example.yml).

A **77-case regression corpus** (35 must-not-redact, 20 adversarial cases added after real gaps were found) guards the detectors, with results reported **per category** in CI. All gated cases pass, and two known limitations are listed openly: millisecond timestamps that happen to pass the Luhn check can be redacted as cards, and unlabeled personal names are not detected. **350 generated property cases** check that known values never reach HTML/Markdown/JSON exports and that links survive redaction. I wrote both the cases and the detectors, so these numbers are a regression guard, not a real-world accuracy estimate. The entropy detector in particular has only been tried on synthetic strings and the sample incidents.

## Privacy and limits

The server binds to `127.0.0.1`. Incident content is not written to disk by the application. The browser holds the original inputs in memory; requests send them only to the local Java process. There is no external runtime service or CDN. Downloaded reports are files you choose to retain and share. JVM heap dumps, operating-system paging, browser extensions, and developer tools are outside this application's storage guarantees.

Redaction is pattern-based, **not a guarantee that all sensitive information has been removed**. IPv6 numeric literals are validated locally without hostname lookup. Bare `::` and `:` separators are not automatically detected; use an explicit custom value if an unspecified IPv6 literal needs hiding. Unlabeled eight-group decimal sequences such as `10:20:30:40:50:60:70:80` are listed as ambiguous and kept automatically. An address field, explicit label such as `peer=`, or brackets makes the same numeric sequence an automatic address match.

Phone detection requires a recognized field or label, such as `phone`, `mobile`, or `telephone`, with 7–15 digits in supported contiguous/grouped forms (up to five groups). Common year-first and day-first dotted/dashed dates are rejected. An extracted phone prefix ending before a timestamp colon is rejected rather than retrying a shorter prefix. Unlabeled phone numbers, names, arbitrary identifiers, and unknown secret formats still require custom values and review. Encoded query parameters and bounded printable UTF-8 base64/JWT/gzip content are inspected; arbitrary encodings and binary content are not. Bodies are optional and truncated at 30,000 characters. Keep original files for complete evidence.

Short/common credentials (under four characters, short all-digit values, or literals such as `true`) are hidden within their sensitive fields or explicitly labeled spans. They are not replaced throughout unrelated text. Automatic global matches use token boundaries. Exact custom values intentionally remain substring matches, including inside displayed correlation IDs; links are formed before redaction, and the interface/report explain this when an ID changes.

The automatic boundary policy treats `_` and `-` as word characters. It preserves `real-secret-suffix`, but also leaves a known secret joined as `token_<secret>` or `prefix-<secret>` unchanged under global matching. The self-check flags surviving long known credentials of this kind. Explicitly labeled credential spans and custom substring values provide coverage. Previously unknown embedded secrets can still evade detection; consider this precision/coverage trade-off when reviewing an incident.

Only explicit version-field shapes such as `version=`, `v=`, JSON `version`, and `x-app-version` get version treatment. Ordinary prose such as `Failed to build 10.0.0.12 image` and `Using release 10.1.2.3 now` does not suppress IP redaction. Version-looking literals are always detected and listed as ambiguous findings; their version-context occurrences default to visible, while actual address occurrences of the same value are masked. **Redact all occurrences** overrides this ambiguity policy, subject to enabled categories. **Keep value** takes precedence if both choices are sent through the API. Export notices and report notes identify automatic ambiguity decisions that left values visible.

The local analysis response includes original detected values for the review view, with originals collapsed by default in the interface. The exported incident excludes this review list and its stable IDs. Values explicitly kept by the user can appear in exported evidence. Clearing the session removes rendered review originals as well as source inputs and review choices.

The browser accepts 10 MiB per file. The API caps input strings at 12 million characters and the total request body at 28 MB, including chunked uploads. Other bounds: 10,000 browser requests, 50,000 log entries, 100,000 text log lines, 20,000 unique redaction candidates, 50 custom values. A full HAR JSON tree and normalized evidence are held in memory; this is an incident-sized tool, not a streaming log warehouse. Long fields are truncated with a visible analysis note. Malformed JSON log lines are skipped with a count.

HTML reports escape imported strings and carry a restrictive CSP with no scripts or external resources. Markdown exports use code fences long enough to contain imported backticks. A local origin/host guard blocks cross-origin API calls and DNS rebinding hosts. See [architecture and trust boundaries](docs/architecture.md).

## API

| Method | Route | Purpose |
| --- | --- | --- |
| GET | `/api/health` | Local engine status |
| GET | `/api/sample` | Fictional HAR and logs |
| GET | `/api/sample/security` | Synthetic security demo and example policy |
| POST | `/api/analyze` | Normalize, correlate, and redact |
| POST | `/api/export/html` | Standalone HTML report |
| POST | `/api/export/markdown` | Markdown report |
| POST | `/api/export/json` | Normalized incident JSON |

All POST endpoints use the same JSON input:

```json
{
  "har": "{\"log\":{\"entries\":[...]}}",
  "logs": "{\"level\":\"ERROR\",\"message\":\"...\"}",
  "title": "Checkout failure",
  "enabledCategories": ["CREDENTIAL", "EMAIL", "IP", "PHONE", "CUSTOM"],
  "customValues": ["customer-name"],
  "includeBodies": false,
  "excludedFindingIds": [],
  "redactFindingIds": [],
  "timestampHints": false,
  "profile": "standard",
  "policyYaml": null,
  "decodeContent": true
}
```

Omit `enabledCategories` to use the selected profile's defaults. An explicit empty array disables all categories. Omit `profile`/`decodeContent` to honor the policy defaults (otherwise standard/on). Paranoid-only detectors run only in the paranoid profile. Categories are `CREDENTIAL`, `EMAIL`, `IP`, `PHONE`, `CUSTOM`, `POLICY`, `CARD`, `IBAN`, `PESEL`, `SUSPECT`. The normalized export excludes original input files, policy text, and the private review map. A CLI-generated title can use the input filename. Internal report IDs (`req-1`, `log-1`) preserve links after redaction. Schema 1.4 adds `incident.security` with profile/decoder/policy counts and a bounded self-check.

`/api/analyze` also returns `findings`, separate from `incident`. Each finding includes a stable ID, original value, categories, source locations, field-scoping flag, substitution count, and ambiguity reasons/counts. Pass IDs in `excludedFindingIds` to keep them or `redactFindingIds` to override ambiguity and redact them. Omit an ID from both sets for Automatic. The same choices are accepted by all export routes. IDs are local review identifiers, not bearer credentials. Export schema `1.2` records exclusion/explicit-redaction counts, an automatically kept ambiguity count, and actual per-category replacement counts, with no original review list or IDs.

## Verification

```sh
mvn verify
node --check src/main/resources/static/app.js
```

The automated suite covers correlation precedence and identifier namespaces, shared traces, unmatched evidence, structured and multiline logs, malformed inputs, secret removal from every export, encoded query parameters, consistent placeholders, overlapping custom rules, concurrent analysis isolation, hostile HTML/Markdown, origin/host guards, and request size limits. CI builds the runnable JAR on Java 17. There is no frontend dependency installation or bundling step.

See [local verification notes](docs/verification.md) for the checked browser workflow and runtime details.

## Docker

```sh
docker build -t bugparcel .
docker run --rm -p 127.0.0.1:8087:8087 bugparcel
```

The container runs as a non-root user. The container itself listens on all interfaces so Docker forwarding works; keep the host port bound to loopback as shown. This local application has no multi-user authentication and should not be exposed as a public service.

## Project layout

```text
src/main/java/dev/bugparcel/
  analysis/   HAR/log parsers, identifier extraction, correlation, redaction
  api/        HTTP endpoints, validation, local origin/host and size guards
  export/     Standalone HTML and Markdown generation
  model/      Immutable API and evidence records
src/main/resources/
  static/     Dependency-free interface: HTML, CSS, ES modules
  samples/    Synthetic checkout incident
src/test/     Behavioral and API integration tests
```

Built by [Roman Sushkin](https://github.com/Nikkilodeonee). MIT licensed.
