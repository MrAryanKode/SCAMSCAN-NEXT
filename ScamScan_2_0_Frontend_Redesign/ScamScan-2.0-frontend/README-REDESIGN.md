# ScamScan 2.0 — Frontend Refresh

This package contains the refreshed frontend source. The redesign is implemented primarily in `src/premium.css`; the existing React application logic, API client, IndexedDB archive, upload validation, OCR/analyze requests, history and report export are preserved.

## Run locally

1. Extract this folder.
2. Open a terminal in the folder containing `package.json`.
3. Run `npm install`.
4. Run `npm run dev`.
5. Keep the ScamScan FastAPI backend running at `http://127.0.0.1:8000`.

## Files
- `src/App.jsx` — existing application and workflows (preserved)
- `src/api.js` — existing FastAPI client (preserved)
- `src/styles.css` — existing base styles (preserved)
- `src/premium.css` — refreshed visual system and responsive overrides
- `src/main.jsx` — existing app entry point

## Notes
- No backend files or endpoints were changed.
- IndexedDB/localStorage persistence remains browser-local.
- The frontend build could not be verified in this Linux packaging environment because the uploaded `node_modules` contained Windows-specific optional Rollup binaries. Run `npm install` on the target machine, then `npm run build`.
