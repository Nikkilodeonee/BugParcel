# Redaction profiles, policies, and self-checks

All detection runs locally. No token is sent to a provider to check whether it is active. Test values and samples are synthetic.

## Profiles and known formats

**Standard** covers labeled credentials/session values, Bearer tokens, AWS access/session key IDs (`AKIA`/`ASIA`), GitHub classic/OAuth/app/fine-grained tokens, Stripe secret/restricted test/live keys, common Slack tokens/webhooks, three-part JWT-shaped tokens, private-key blocks, URL user-info credentials, email, IP addresses, and labeled phones. Format matching cannot prove a credential is valid or exhaustive coverage of every provider's token variants. JWT signatures are not verified. An unfinished private-key block hides the rest of its field.

Provider families were checked against the public [Gitleaks rules](https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml). The implementation keeps its own bounded matchers and retains the earlier broad OpenAI/GitHub detectors for compatibility. It is not the Gitleaks or TruffleHog engine and does not inherit their complete coverage.

**Paranoid** adds:

| Detector | Check | Important limit |
| --- | --- | --- |
| Cards | 13–19 digits, optional spaces/dashes, Luhn; rejects repeated identical digits | Other numeric identifiers can pass Luhn. This does not verify a real card. |
| IBAN | Recognized country length, alphanumeric shape, MOD-97 | Uppercase compact or space-separated form. No account/BBAN ownership verification. Country-length facts checked against the [Apache Commons Validator registry](https://github.com/apache/commons-validator/blob/master/src/main/java/org/apache/commons/validator/routines/IBANValidator.java). |
| PESEL | 11 digits, encoded birth date, weights 1/3/7/9/1/3/7/9/1/3 and check digit | A valid shape/checksum does not establish that an ID was assigned. [Polish government specification](https://www.gov.pl/web/gov/czym-jest-numer-pesel). |
| Entropy suspect | 24–256 ASCII token characters, letters and digits, Shannon entropy at least 4.3 bits/character | A heuristic: harmless hashes and identifiers can match. Known correlation-ID fields are exempt from entropy checks only; credential patterns still apply. |

Paranoid matches are reviewed like other values. Category switches can disable individual groups. Names and unknown formats still need exact custom values or policy rules. An all-zero separator `::`, dates in phone fields, and explicit version-field ambiguity retain the existing context rules.

## Team policy

The CLI automatically reads **`bugparcel.yml` in its current working directory**. It does not search parent directories. Use `--policy path.yml` for another file or `--no-policy` to disable discovery. The web interface only loads a file you select in **Redactions → Scanning & team policy**; the web server does not auto-read a local policy file.

```yaml
version: 1
defaultProfile: paranoid
decodeContent: true
rules:
  - id: internal-customer-id
    pattern: 'CUST-[0-9]{6}'
    fields: ['* request body/customerId']
  - id: internal-label
    pattern: 'TEAM-[A-Z]{5}'
    fields: ['log-* message']
allowlists:
  - values: ['public@example.test']
    fields: ['log-* message']
  - pattern: '^demo-[0-9]+$'
    fields: ['* request body/publicReference']
```

`pattern` replaces its complete matched span. `fields` defaults to `['*']`; omitting it makes a rule apply throughout included text. Field globs are case-sensitive full-location matches: `*` matches any text and `?` one character. Inspect **Found in** in the local review to see paths. Examples: `req-1 request headers/x-api-key`, `req-1 request body/customerId`, `log-1 message`. Encoded findings add ` decoded base64` / ` decoded JWT claims` to their location. Use an ending `*` when a field rule should include its decoded descendants.

Allowlists compare the entire detected original value, by exact `values` or full regex match, at matching locations. A field-scoped exception does not allow the same value in other fields. An encoded container can have several categories; keeping one decoded child does not disable another overlapping detector. The review shows allowlisted occurrence counts; exports include residual warnings but not policy text, rule IDs/regexes, allowlist originals, or the review map.

Precedence: **Keep value → matching policy allowlist → Force/Automatic, subject to category switches and field scope**. Force cannot override an allowlist. Remove/narrow the exception when that is wanted. Another active overlapping match can still cover a kept span.

Explicit CLI `--profile standard|paranoid` (or `--paranoid`) overrides the file's default profile. `--no-decode` overrides its decoding setting. The UI profile/decoder controls likewise override an imported policy until it is cleared. Clearing a policy restores standard defaults.

Policy regexes use [RE2/J](https://github.com/google/re2j) for linear-time matching; Java lookarounds/backreferences are unsupported. YAML has a 64 KiB limit, depth 8, unique keys, safe primitive types, and no aliases, arbitrary object tags, includes, or file/network references. Limits: 20 custom rules, 50 allowlists, 512 characters per regex, 20 field globs per item, 100 exact values per allowlist (1,024 characters each). Rule IDs are unique lowercase labels. Unknown fields and malformed policies fail explicitly without echoing their content.

The [example policy](../src/main/resources/samples/bugparcel.example.yml) is also downloadable in the UI. **Security sample** loads synthetic provider tokens, encoded content, private-key text, and checksum identifiers. Apply its example team policy to see scoped rules, an intentional exception, and a nonzero self-check.

## Decoded content

Decoded-content inspection defaults **on**. Base64/base64url tokens of at least 16 encoded characters are considered only if they decode to valid printable UTF-8. Three-part JWT headers/claims are inspected as JSON; signatures are never verified or regenerated. If decoded contents match an enabled detector, the original encoded container is replaced as a whole. Decoded originals appear only in local review. Custom literals and policy rules also run on decoded contents.

With bodies enabled, HAR `encoding: base64` text is decoded before redaction; gzip magic bytes inside that base64 container are decompressed. Nonstandard `encoding: gzip` is accepted only for base64-wrapped gzip bytes. Exports contain the decoded, redacted body text. A normal HAR body already decompressed by the browser is not decompressed again merely because its HTTP header says gzip. Binary/unsupported/invalid bodies are omitted with a note. Bodies remain excluded by default.

Bounds: two nested token-encoding layers; 64 KiB decoded/decompressed per value; 90,000 encoded input characters per decode; 1 MiB decoded bytes and 1,000 decode attempts per inspection stage. HAR body normalization and redaction each own a bounded decoder. Excess size/depth/work produces a visible limit note; raw rejected HAR bytes are not exported. Inspection does not extract archives or decrypt encrypted tokens/JWE. Arbitrary encodings, truncated strings, and unlabeled phone/name content can remain opaque.

## Export self-check

After redaction, a second pass inspects the exact normalized evidence shared by HTML, Markdown, and JSON exporters. It applies the selected profile and decoding setting, checks custom/policy patterns again, and searches for long known credentials/custom literals that remain embedded past automatic token boundaries. A separate bounded multi-pattern matcher performs that literal check. This is a check of included evidence, not omitted bodies or original input files, and not a proof that a report is safe to share.

The badge says **“0 remaining pattern/known-value matches”** only within that displayed scope. Remaining matches, including explicitly kept, category-disabled, ambiguous, or allowlisted values, produce an amber count. Disabling decoding or reaching limits shows a **Limited check**. The report carries the same scope/counts and at most 50 issue summaries containing categories and internal request/log references; no original values or review hashes. A literal scan is bounded to 500,000 trie nodes and 4 million terminal visits; exceeding its bound marks the check incomplete.

`--strict` still fails for unresolved automatic IP ambiguity and now also fails for unexpected residuals or incomplete scans (exit 3). Explicitly kept/disabled/allowlisted matches remain warnings and are not by themselves strict failures. The report is still written so it can be inspected. Standard mode does not inspect paranoid-only identifier/entropy shapes; disabling decoding limits its scope even when no remaining match is found.

The `_`/`-` automatic-boundary trade-off remains: a previously unknown secret embedded in an arbitrary identifier may evade standard detection. Long already-discovered credentials are checked for such residuals; custom substring values cover a specific value everywhere. Detectors and self-checks share some rules, so they can share blind spots. Review is still required.

## Measured tests

The checked-in [corpus](../src/test/resources/redaction/corpus.json) has **57 synthetic cases**, including **25 negative cases**. Exact automatic redaction decisions currently yield **32 true positives, 0 false positives, 0 misses: 100% precision and recall on this corpus only**. This small fixture result is not a real-world accuracy estimate. Negative cases cover dates, separators, version contexts, key boundaries, invalid checksums, public key blocks, and harmless low-entropy text. Add real-format regressions using synthetic values before making broader claims.

`RedactionCorpusTest` measures decisions and checks known-value removal from all three exports. It writes `target/redaction-corpus-metrics.json`; CI gates the labeled cases and a 98% floor, then publishes the numbers and artifact via `scripts/report-corpus.mjs`.

Two [jqwik](https://jqwik.net/docs/1.9.3/user-guide.html) properties run **350 generated cases** with fixed reproducible seeds and shrinking: provider secrets in direct/encoded evidence must be absent from every export, and exact custom values embedded in IDs must disappear while links remain intact. These are bounded property tests, not a proof over arbitrary encodings or all possible secrets. Reproduce with:

```text
mvn -Dtest=RedactionPropertiesTest,RedactionCorpusTest,RedactionTierTwoTest test
node scripts/report-corpus.mjs
```
