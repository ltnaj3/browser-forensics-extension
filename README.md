# Browser Forensics Extension

A browser extension that records local forensic telemetry for:

- navigation activity
- request behavior
- downloads
- extension inventory and posture
- page snapshots
- performance metrics such as LCP/FCP/CLS

## Goals

- preserve local forensic signal
- reduce noisy duplication with canonical grouping and coalescing
- support future endpoint synchronization with a backend recorder
- enable cross-correlation between browser-local and endpoint-side evidence

## Current capabilities

- request grouping and coalescing
- page snapshot capture
- extension inventory diagnostics
- performance signal capture
- local export/debug helpers

## Planned capabilities

- endpoint enrollment
- batch upload
- config fetch
- retry/backoff
- cross-recorder correlation

## Debugging

Open the extension service worker console and use:

```javascript
await forensicsDebug.dumpLatestBatch()
await forensicsDebug.dumpAllForensicsEvents()
await forensicsDebug.dumpEventsByType('request_completed_summary')
await forensicsDebug.dumpPerfEvents()
await forensicsDebug.dumpExtensionDiagnostics()
await forensicsDebug.downloadForensicsEventsJson()
```
