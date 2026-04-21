// Generate narration.mp3 from narration.txt via OpenAI TTS.
//
// Usage:
//   export OPENAI_API_KEY=sk-...
//   node generate-narration.mjs
//
// Defaults: onyx voice, tts-1-hd, speed=0.88 (calibrated for this script vs 81.8s target video).
// Tune SPEED=X if duration drifts.

import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const apiKey = process.env.OPENAI_API_KEY;
if (!apiKey) { console.error('set OPENAI_API_KEY'); process.exit(1); }

const voice = process.env.VOICE || 'onyx';
const model = process.env.MODEL || 'tts-1-hd';
const speed = parseFloat(process.env.SPEED || '0.88');

const input = await fs.readFile(path.join(here, 'narration.txt'), 'utf8');
const wordCount = input.trim().split(/\s+/).length;

console.log(`voice=${voice}  model=${model}  speed=${speed}`);
console.log(`narration: ${wordCount} words, ${input.length} chars`);
console.log('calling OpenAI...');

const t0 = Date.now();
const resp = await fetch('https://api.openai.com/v1/audio/speech', {
  method: 'POST',
  headers: {
    Authorization: `Bearer ${apiKey}`,
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({ model, voice, input, response_format: 'mp3', speed }),
});

if (!resp.ok) {
  console.error(`OpenAI error: ${resp.status}`);
  console.error(await resp.text());
  process.exit(1);
}

const buf = Buffer.from(await resp.arrayBuffer());
const outPath = path.join(here, 'narration.mp3');
await fs.writeFile(outPath, buf);
console.log(`wrote ${outPath} (${(buf.length / 1024).toFixed(1)} KB) in ${Date.now() - t0}ms`);
console.log('');
console.log('Target: 81.8s. Check with:');
console.log('  ffprobe -v error -show_entries format=duration -of default=nw=1:nk=1 assets/narration.mp3');
