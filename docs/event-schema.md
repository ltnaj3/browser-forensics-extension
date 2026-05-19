# Event Schema

## Envelope
Each stored event includes:

- `schemaVersion`
- `seq`
- `sensorId`
- `sessionId`
- `timestamp`
- `monotonicMs`
- `type`
- `provenance`
- `confidence`
- `tags`
- `interactionContext`
- `data`
- `integrity`

## Common event categories

- navigation events
- request events
- request summaries
- page events
- page snapshots
- download events
- extension inventory events
- extension diagnostics events
- performance events

## Coalesced events
Coalesced events may include:

- `coalesced`
- `repeatCount`
- `occurrences`
- `variationSummary`

## Request summaries
Request summary events may include:

- `canonical`
- `requestIds`
- `frameIds`
- `documentIds`
- `fullUrls`
- `urlHits`
- `remoteIps`
- `fromCacheValues`
- `statusLines`

## Performance events
Performance-related `page_event` payloads may include:

- `page_fcp`
- `page_lcp_candidate`
- `page_lcp`
- `page_cls`
- `page_nav_timing`
- `page_perf_summary`
- `extension_perf_measurement`
