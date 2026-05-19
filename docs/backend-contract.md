# Backend Contract

This extension is expected to sync with a future endpoint recorder / ingestion API.

## Proposed endpoints

- `POST /api/forensics/installations/register`
- `POST /api/forensics/batches`
- `POST /api/forensics/heartbeat`
- `GET /api/forensics/config`

## Proposed registration fields

- `sensorId`
- `sessionId`
- `extensionVersion`
- `device metadata`
- `browser metadata`

## Proposed batch upload fields

- `schemaVersion`
- `sensorId`
- `sessionId`
- `batchId`
- `parentBatchId`
- `splitDepth`
- `createdAt`
- `count`
- `events`

## Design principles

- local-first evidence collection
- upload opportunistically
- preserve integrity metadata
- tolerate offline operation
- keep schema versioned
