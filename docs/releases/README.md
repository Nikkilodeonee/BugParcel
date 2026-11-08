# Publishing a release

The `Release` workflow builds on a pushed stable version tag such as `v1.4.0`. The tag must match `pom.xml`; release packaging derives its filenames from that version. Run the normal checks before tagging:

```sh
npm run check
mvn verify
```

Update the versioned notes in `docs/releases/`, keep `docs/demo.gif` current, then commit and push the source. Create an annotated tag at that commit and push it:

```sh
git tag -a v1.4.0 -m "BugParcel 1.4.0"
git push origin v1.4.0
```

CI runs Java 17 tests and JavaScript syntax checks, generates the synthetic standalone report, checks it for scripts/external assets and fixture secrets, and packages the ZIP. The publishing job verifies SHA-256 checksums, creates a draft release, attaches the ZIP/JAR/HTML/GIF/checksums, then publishes it. Only the publishing job has repository write permission. A rerun can resume an unpublished draft; it refuses to overwrite an already published release. Do not move published version tags.

For a local packaging check after building, run `scripts/prepare-release.ps1` with Java and Node available. Outputs are under ignored `artifacts/publish/`; release uploads come from CI, not the local build. The sample HTML is generated from bundled fictional fixtures with bodies included and strict redaction checking.

The GIF consists of six real browser screenshots, each displayed for three seconds. To update it, capture the empty workspace, linked payment logs, detected-value review, waterfall, synthetic before/after comparison, and HTML export dialog into `.cache/release-demo/01-start.jpg` through `06-export.jpg`. Run `scripts/build-demo.py` with Python/Pillow; `--font` accepts a local TrueType font. Screenshot capture and GIF assembly are development tasks and require no dependency in the app or CI.
