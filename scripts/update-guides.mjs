import { readFile, writeFile } from 'node:fs/promises';
import { requestIdGuides } from '../src/main/resources/static/request-id-guides.js';
const readme = new URL('../README.md', import.meta.url);
const start = '<!-- request-id-guides:start -->';
const end = '<!-- request-id-guides:end -->';
const block = requestIdGuides.map(g => '### ' + g.name + '\n\n' + g.note + '\n\n```' + g.language + '\n' + g.code + '\n```\n\n[API reference](' + g.source + ')').join('\n\n');
const original = await readFile(readme, 'utf8');
if (!original.includes(start) || !original.includes(end)) throw new Error('README guide markers are missing');
await writeFile(readme, original.slice(0, original.indexOf(start)) + start + '\n\n' + block + '\n\n' + original.slice(original.indexOf(end)));
