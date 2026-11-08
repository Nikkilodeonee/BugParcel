# Input formats and retrieval

Tier 4 / BugParcel 1.4.0 / incident schema 1.6.

## Capture adapters

Every adapter produces a bounded HAR-shaped object before `HarParser`, identifier correlation, redaction, and the export self-check. Adapters neither execute collection scripts nor fetch resource references. Original files, archive paths, connection/certificate metadata, and private review maps are excluded from reports. `incident.sources` contains a fixed format label and capture-stream/log-file counts.

- **HAR:** normal browser and Playwright HAR, optionally gzip compressed. A ZIP can contain one HAR plus body attachments. Embedded text/base64/gzip bodies retain the existing decoder controls. `_file` references are relative to the HAR within the supplied ZIP; Playwright trace `_sha1` bodies are looked up under `resources/`. Missing bodies produce a note. No filesystem/HTTP fallback exists. Playwright's attached-body storage is described by its [HAR recorder](https://github.com/microsoft/playwright/blob/main/packages/playwright-core/src/server/har/harRecorder.ts).
- **Playwright trace ZIP:** reads `.network` JSONL `resource-snapshot` events with HAR-shaped snapshots, including attached request/response bodies when bodies are enabled. It excludes `.trace` action/DOM/console events, screenshots, source code, and non-network attachments. Multiple network streams retain deterministic file order. This is a network importer, not a Trace Viewer replacement. Future trace versions that change the network shape may need HAR export. [Trace Viewer](https://playwright.dev/docs/trace-viewer), [network recorder](https://github.com/microsoft/playwright/blob/main/packages/playwright-core/src/server/trace/recorder/tracing.ts).
- **Charles XML:** File → Export → XML. Reads HTTP transaction method/protocol/host/port/path/query, epoch start/end times, headers, response status, and text/base64 bodies. Charles's known external DTD declaration is stripped without resolving it. Internal DTDs/entities are rejected. XML depth is capped at 32 and attributes at 100 per element. Native `.chls`, CSV summaries, and Charles trace text are not supported by this XML adapter. [Charles export documentation](https://www.charlesproxy.com/documentation/using-charles/export/), [published XML DTD](https://www.charlesproxy.com/dtd/charles-session-1_0.dtd), [JAXP security controls](https://docs.oracle.com/en/java/javase/17/security/java-api-xml-processing-jaxp-security-guide.html).
- **mitmproxy:** accepts HAR and native typed-netstring **HTTP flow format 21**. The native adapter reads selected request/response fields and ignores connection state, certificates, WebSocket messages, and non-HTTP flows. It parses data only, with depth/node/length limits. Other native format versions are rejected rather than guessed. Export them through `mitmdump -nr capture.mitm --set hardump=capture.har`. [Flow writer](https://github.com/mitmproxy/mitmproxy/blob/main/mitmproxy/io/io.py), [format version](https://github.com/mitmproxy/mitmproxy/blob/main/mitmproxy/version.py), [HAR option](https://docs.mitmproxy.org/stable/concepts/options/).
- **Newman JSON:** use `newman run collection.json --reporters json --reporter-json-export run.json`. Reads `run.executions`: request method/URL, explicit headers, raw/urlencoded bodies, response code/status/headers/time, and Buffer-stream or text response bodies. Disabled headers/parameters are excluded. File/multipart bodies, scripts, variables, certificate files, and auth helpers are not evaluated. Missing per-request wall clocks remain untimed. Failed assertions are not converted into HTTP failures. [Newman JSON reporter](https://github.com/postmanlabs/newman#json-reporter).
- **Postman desktop run JSON:** reads the aggregate `results` URL, recorded method when present, final response code/name, and reported duration. Headers/bodies and per-execution times are not reconstructed from aggregates. A missing method is `UNKNOWN`, preventing replay export. Use Newman JSON when detailed evidence is needed. Collections/environments alone are not run reports. [Exporting collection runs](https://learning.postman.com/docs/tests-and-scripts/running-collections/intro-to-collection-runs/).

Unavailable negative HAR/Playwright response statuses normalize to `0` (network failure). Unavailable durations display as zero with an explicit warning; the resulting completion position is approximate. Source clocks can differ. IDs establish relationships; input format or time proximity does not establish causation.

The examples are fictional format-shaped fixtures derived from `checkout.har`, not recordings of a real customer incident. Generate them with `scripts/generate-input-samples.ps1` (Node required for fixture generation only). `bugparcel sample --inputs` copies the bundled variants; the UI input guide offers a Playwright trace + ZIP logs demo.

## Log files, folders, and archives

```sh
bugparcel report trace.zip --logs ./logs -o report.html
bugparcel report capture.har --logs "logs/*.log" --logs worker.ndjson -o report.html
bugparcel report capture.har --logs "logs/**/*.log.gz" -o report.json
bugparcel report charles.xml --logs logs.zip --include-bodies -o report.html
```

Quote globs so BugParcel receives the pattern on both Windows and Unix. `*`, `?`, Java glob character classes/braces, and recursive `**` are supported. Recursive patterns include zero-directory cases, with at most 32 expanded pattern combinations and 512 characters in a path/glob. Discovery sorts and deduplicates selected files, does not follow symlinks, and fails on discovery/depth limits. Explicitly named regular files may use other extensions; directory/ZIP discovery selects `.log`, `.txt`, `.ndjson`, `.jsonl`, `.json`, `.out`, `.err`, and gzip inputs (plus ZIPs for CLI directories).

JSON arrays are converted to object-per-line streams before combining with text/NDJSON. Each file retains its log-format detection; source line numbers refer to the combined stream, not an exported local filename. Bracket-prefixed text remains text. UTF-8 and BOM-marked UTF-16 are supported; malformed text and binary inputs fail explicitly.

Gzip logs and ZIP members are decoded in memory. One layer of gzip is allowed inside a log ZIP. Nested ZIPs, gzip-wrapped archives, encrypted/corrupt entries, duplicate archive names, absolute/drive paths, parent traversal, and control-character names are rejected. Unsupported ZIP members are counted and omitted. Nothing is extracted to disk.

### Limits

| Boundary | Limit |
| --- | --- |
| Uploaded file / CLI capture or log file | 10 MiB |
| Normalized capture / combined UTF-8 log text | 12,000,000 bytes each |
| ZIP expansion | 32 MiB total; 12,000,000 bytes per entry; 2,000 entries |
| Materialized referenced bodies | 12,000,000 bytes across references, including repeated references |
| Selected log files / expanded text parts | 200 |
| CLI directory discovery | 5,000 entries; 20 directory levels; no symlink following |
| Combined CLI log files before expansion | 32 MiB |
| Capture requests / Playwright network events | 10,000 / 30,000 |
| Typed-netstring parsing | 64 levels, 500,000 nodes, lengths bounded by the input |
| Local HTTP request | 28,000,000 bytes total, including JSON/base64 and both comparison sides |

Input/archive/discovery limits fail atomically, rather than silently returning an apparently complete truncated archive. Existing parser entry, field, and body limits still apply after normalization and produce their normal warnings. Unknown or missing fields stay unavailable; self-check results cover only included normalized evidence.

## Pipeline recipes

```sh
docker logs api 2>&1 | bugparcel report capture.har --logs - -o report.html
kubectl logs deploy/api --timestamps | bugparcel report capture.har --logs - -o report.html
journalctl -u api -o cat | bugparcel report capture.har --logs - -o report.html
docker compose logs --no-color --no-log-prefix api | bugparcel report capture.har --logs - -o report.html
```

Stdin can supply one capture or log input once. Diagnostics go to stderr; `-o - --format md` writes just the report to stdout. Keep source timestamps/IDs when possible. Removing Compose's prefix avoids mixing service prefixes into JSON lines; the flags are documented in [Docker Compose logs](https://docs.docker.com/reference/cli/docker/compose/logs/).

## Explicit pull mode

Pull options are available only in CLI `report`, `review`, and `replay`. Ordinary local imports do not contact a service. The browser/API has no URL-fetch field or pull route, and imported captures cannot request a fetch. `diff` accepts saved local log evidence so each side uses a fixed capture.

```sh
# Local file URI; on Unix use file:///var/log/api.log
bugparcel report capture.har --logs-url "file:///C:/logs/api.log" -o report.html

# Raw log response, optionally .gz/ZIP by content
bugparcel report capture.har --logs-url https://logs.example.test/incident.log -o report.html

# Loki: a user-chosen stream selector plus a safely quoted literal ID line filter
bugparcel report capture.har --loki http://127.0.0.1:3100 --selector '{app="api"}' --request-id pay-42 --since 15m --pull-limit 2000 -o report.html

# Elasticsearch: the ID field must support exact term matching in your mapping
bugparcel report capture.har --elasticsearch https://search.example.test --index 'logs-*' --id-field requestId.keyword --request-id pay-42 --since 2026-11-07T14:00:00Z --until 2026-11-07T15:00:00Z --auth-env BUGPARCEL_AUTH -o report.html
```

`BUGPARCEL_AUTH` must hold the complete Authorization value, such as a Bearer, Basic, or ApiKey header. Set it in your shell/secret manager; BugParcel reads it only when `--auth-env` names it. Never put credentials in a URL. Endpoint URLs, query options, and authorization values are not copied into report metadata or service-error messages. Retrieved **evidence** still goes through the normal review/redaction pipeline, including intentional keeps/allowlists.

File URLs must name local regular files with an empty authority; network shares/UNC file authorities are rejected. HTTP/HTTPS raw URLs are GET requests. Loki sends GET `/loki/api/v1/query_range` with the selector, a JSON-quoted literal `|=` ID filter, an explicit interval, forward direction, and a result limit. It imports stream lines with their stored Loki timestamp as the capture clock; labels and unrelated service metadata are not made into invented IDs. Elasticsearch sends POST `/{index}/_search` with a JSON term filter, `@timestamp` range, ascending time sort, and a size limit, importing `_source` objects only. Supply the correct exact-match ID field for your index. [Loki query API](https://grafana.com/docs/loki/latest/reference/loki-http-api/), [Elasticsearch search API](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-search).

The default interval is 15 minutes, maximum 24 hours. `--since` accepts `15m`, `1h`, seconds, or an ISO instant; `--until` defaults to now and needs an ISO instant. Default result limit is 1,000, configurable from 1–10,000. No automatic pagination or background polling occurs. Reaching Loki's limit, omitted Elasticsearch hits, shard failures, and partial/timed-out service results are marked limited and fail `--strict`.

HTTP redirects are never followed. TLS uses normal Java certificate validation; there is no insecure bypass. Authorization requires HTTPS except literal loopback development endpoints. Responses have a 10 MiB body limit, bounded decompression, and a 20-second overall deadline that includes the body. These controls use a streaming [Java BodySubscriber](https://docs.oracle.com/en/java/javase/17/docs/api/java.net.http/java/net/http/HttpResponse.BodySubscriber.html). Service error bodies are not echoed. Authentication formats, tenant/proxy requirements, custom index mappings, and real deployment permissions remain the operator's configuration; tests use local synthetic HTTP services only.
