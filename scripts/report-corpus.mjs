import { readFile, appendFile } from 'node:fs/promises';
const metrics = JSON.parse(await readFile(new URL('../target/redaction-corpus-metrics.json', import.meta.url), 'utf8'));
const summary = `## Synthetic redaction corpus\n\n${metrics.cases} cases (${metrics.negativeCases} negative). Precision ${(100*metrics.precision).toFixed(2)}%; recall ${(100*metrics.recall).toFixed(2)}%. TP ${metrics.truePositives}, FP ${metrics.falsePositives}, FN ${metrics.falseNegatives}.\n\n${metrics.scope}.\n`;
process.stdout.write(summary);
if (process.env.GITHUB_STEP_SUMMARY) await appendFile(process.env.GITHUB_STEP_SUMMARY, summary);
