import { readFile, appendFile } from 'node:fs/promises';
const metrics = JSON.parse(await readFile(new URL('../target/redaction-corpus-metrics.json', import.meta.url), 'utf8'));
const pct = (value) => value === null ? 'n/a' : `${(100 * value).toFixed(1)}%`;
const rows = Object.entries(metrics.byCategory)
  .map(([name, c]) => `| ${name} | ${c.cases} | ${c.truePositives} | ${c.falsePositives} | ${c.falseNegatives} | ${pct(c.precision)} | ${pct(c.recall)} |`)
  .join('\n');
const limits = metrics.knownLimitations.length
  ? metrics.knownLimitations.map((k) => `- \`${k.id}\` (${k.category}): ${k.behavior}`).join('\n')
  : '- none';
const summary = `## Redaction regression corpus

${metrics.cases} gated cases (${metrics.negativeCases} must-not-redact, ${metrics.adversarialCases} adversarial, added after a gap or false positive was found). TP ${metrics.truePositives}, FP ${metrics.falsePositives}, FN ${metrics.falseNegatives}; precision ${pct(metrics.precision)}, recall ${pct(metrics.recall)} on these fixtures only.

| Category | Cases | TP | FP | FN | Precision | Recall |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
${rows}

Known limitations (documented, not part of the gated numbers):
${limits}

${metrics.scope}.
`;
process.stdout.write(summary);
if (process.env.GITHUB_STEP_SUMMARY) await appendFile(process.env.GITHUB_STEP_SUMMARY, summary);
