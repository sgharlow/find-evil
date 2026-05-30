# Narration cue sheet — find-evil demo video

**Video:** `C:\Users\sghar\Videos\find-evil-demo-final.mp4` — 2:49.7, 1080p/60fps, silent.
**Source text:** `assets/narration.txt` (8 paragraphs, in order = 8 segments below).
**Harness pace:** OpenAI TTS `onyx` @ speed 0.88 ≈ **2.30 words/sec (138 wpm)** — measured from the prior `narration.mp3`.

> The harness reads `narration.txt` as ONE continuous pass (~122s of speech). The video is 169.7s
> with 8 cut points, so **place each paragraph's audio at its segment start** (windows below) rather
> than laying one continuous track — otherwise the audio finishes ~48s before the video ends.
> Every paragraph is sized to fit its segment at a relaxed pace (margins are all positive), so no
> segment forces you to rush or drag.

| # | Segment            | Video window | On screen                                              | Words | ~VO  | Headroom |
|---|--------------------|--------------|--------------------------------------------------------|-------|------|----------|
| 1 | Intro slide        | 0:00–0:05    | Title slide                                            | 10    | 4.3s | +0.7s    |
| 2 | Architecture       | 0:05–0:20    | Architecture diagram                                   | 34    | 14.8s| +0.2s    |
| 3 | Live core          | 0:20–1:36    | validate 49/49 → live investigation/self-correct → tamper HALT → audit trail | 106 | 46.1s | +29.6s |
| 4 | Provenance still   | 1:36–1:45    | audit_trail.jsonl UUID chain                           | 18    | 7.8s | +1.2s    |
| 5 | Simulated attack   | 1:45–2:27    | video_demo.py 7-phase attack, ACCEPTED findings        | 66    | 28.7s| +13.3s   |
| 6 | STIX still         | 2:27–2:37    | bundle.stix.json                                       | 21    | 9.1s | +0.9s    |
| 7 | Credibility card   | 2:37–2:45    | 554 tests / MITRE / MIT                                | 16    | 7.0s | +1.0s    |
| 8 | Outro slide        | 2:45–2:50    | Outro slide                                            | 9     | 3.9s | +1.1s    |

**Total:** 280 words · ~122s of speech across 169.7s of video.

## Notes
- **Live core (segment 3)** has ~30s of headroom on purpose — there are long stretches where commands
  scroll on screen. Spread the 106 words across the four beats (proof / investigation / tamper / audit
  trail) and let the terminal breathe between them.
- To generate the audio: `cd assets && export OPENAI_API_KEY=sk-... && node generate-narration.mjs`
  (produces `narration.mp3`). For per-segment clips, run it on one paragraph at a time, or split the
  single mp3 at the natural paragraph pauses.
- All numbers are spelled for clean TTS ("two-point-one", "forty-nine"). "SHA-256" and "UUID" read fine.
