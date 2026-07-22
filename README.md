# NLP Metadata Solution

[![Deploy to GitHub Pages](https://github.com/username123abc123/nlpmetadata/actions/workflows/deploy.yml/badge.svg)](https://github.com/username123abc123/nlpmetadata/actions/workflows/deploy.yml)

## Fully offline

The quantized model, its tokenizer, and the ONNX Runtime WASM binaries are committed
under `public/`, and transformers.js is locked to same-origin assets with
`allowRemoteModels = false`. After the initial page load the app makes no network
requests at all. That constraint is deliberate: the demo targets restricted networks
where pulling a model from a hub at runtime is not an option.

## Quick start

Requires Node 22 or newer.

```bash
npm ci
npm run dev        # Vite dev server
```

Other scripts:

```bash
npm test           # Vitest unit tests plus an embedding integration test
npm run build      # type-check and production build into dist/
npm run preview    # serve the production build
npm run e2e        # Playwright smoke test against a running preview:
                   #   E2E_URL=http://localhost:4173/nlpmetadata/ npm run e2e
```

## Using the demo

Start on the Stable feed: field names match the schema and everything behaves.
Switch to the Drifted feed and the same activity arrives with renamed, restructured
fields. Coverage drops. Rules that depend on the missing fields go quiet without a
single error to tell you so, and the correlation between the two event streams
disappears. Hit Repair to let the mappers fill the gaps and re-run the pipeline;
each KPI then shows its value before and after. Reset undoes the repairs, and Export
patch downloads the applied mappings as JSON.

## Project structure

```
src/
  pipeline/    ingest → adapt (flatten) → normalize → correlate / drift / detections
  nlp/         heuristic + embedding mappers, suggestion selection, value shapes
  schema/      canonical schema (schema.json)
  data/        Suricata and Sysmon samples, stable and drifted variants
  ui/          single-page UI in plain TypeScript
  tests/       Vitest suites
public/
  models/      quantized all-MiniLM-L6-v2 (ONNX plus tokenizer)
  wasm/        ONNX Runtime WASM binaries
scripts/       Playwright e2e smoke test and a mapping debug helper
```

## Deployment

Every push to `main` runs the workflow in `.github/workflows/deploy.yml`, which
tests, builds with a Vite base of `/nlpmetadata/`, and publishes `dist/` to GitHub
Pages.

## Status

This is a proof of concept. The data is synthetic and the schema is deliberately
small. The detection rules are there to make breakage visible, not to catch real
attackers. The point is to let you watch the whole loop in one page: drift breaks
the pipeline silently, the report makes the damage visible, and a repair puts the
mapping back together.
