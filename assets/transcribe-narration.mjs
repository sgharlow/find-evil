// Transcribe narration.mp3 -> narration.srt via OpenAI Whisper for burned-in captions.
// Usage: OPENAI_API_KEY=sk-... node transcribe-narration.mjs

import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const apiKey = process.env.OPENAI_API_KEY;
if (!apiKey) { console.error('set OPENAI_API_KEY'); process.exit(1); }

const mp3 = await fs.readFile(path.join(here, 'narration.mp3'));
const form = new FormData();
form.append('file', new Blob([mp3], { type: 'audio/mpeg' }), 'narration.mp3');
form.append('model', 'whisper-1');
form.append('response_format', 'srt');

console.log('calling Whisper...');
const t0 = Date.now();
const resp = await fetch('https://api.openai.com/v1/audio/transcriptions', {
  method: 'POST',
  headers: { Authorization: `Bearer ${apiKey}` },
  body: form,
});

if (!resp.ok) {
  console.error(`Whisper error ${resp.status}:`, await resp.text());
  process.exit(1);
}

const srt = await resp.text();
const outPath = path.join(here, 'narration.srt');
await fs.writeFile(outPath, srt, 'utf8');
console.log(`wrote ${outPath} (${srt.length} chars) in ${Date.now() - t0}ms`);
console.log(`cue count: ${(srt.match(/^\d+$/gm) || []).length}`);
