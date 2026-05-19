const STORAGE_KEYS = {
  SENSOR_ID: 'forensics_sensor_id',
  BATCH_INDEX: 'forensics_batch_index'
};

const STORAGE_LIMITS = {
  MAX_BATCHES: 100,
  MAX_BATCH_BYTES_ESTIMATE: 100000,
  MAX_TOTAL_BYTES_ESTIMATE: 8 * 1024 * 1024
};

const Recorder = {
  schemaVersion: '1.0.0',
  sensorId: null,
  sessionId: crypto.randomUUID ? crypto.randomUUID() : `session-${Date.now()}`,
  startedAt: Date.now(),
  seq: 0,
  queue: [],
  maxQueueSize: 100,
  flushIntervalMs: 5000,
  previousEventHash: null,
  tabState: new Map(),
  extensionInventoryIntervalMs: 15 * 60 * 1000,
  lastExtensionInventoryHash: null,
  lastExtensionInventoryById: new Map(),
  dedupWindowMs: 1500,
  recentEventFingerprints: new Map(),
  redirectChains: new Map(),
  lastPageSnapshotFingerprintByTab: new Map(),
  lastPageSnapshotAtByTab: new Map(),
  pageSnapshotMinIntervalMs: 5000,
  requestBeforeGroups: new Map(),
  requestCompletedGroups: new Map(),
  requestGroupWindowMs: 2000,
  recentCoalescedEvents: new Map(),
  coalesceWindowMs: 5000
};

async function initializeSensorIdentity() {
  const existing = await chrome.storage.local.get([STORAGE_KEYS.SENSOR_ID]);
  if (existing[STORAGE_KEYS.SENSOR_ID]) {
    Recorder.sensorId = existing[STORAGE_KEYS.SENSOR_ID];
    return;
  }

  const sensorId = crypto.randomUUID ? crypto.randomUUID() : `sensor-${Date.now()}`;
  Recorder.sensorId = sensorId;
  await chrome.storage.local.set({ [STORAGE_KEYS.SENSOR_ID]: sensorId });
}

function nowIso() {
  return new Date().toISOString();
}

function nowMs() {
  return Date.now();
}

function monotonicMs() {
  return Date.now() - Recorder.startedAt;
}

function newBatchId() {
  return crypto.randomUUID ? crypto.randomUUID() : `batch-${Date.now()}-${Math.random()}`;
}

async function sha256Hex(input) {
  const bytes = new TextEncoder().encode(input);
  const hashBuffer = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function estimateBytes(value) {
  try {
    return new TextEncoder().encode(JSON.stringify(value)).length;
  } catch {
    return JSON.stringify(value || '').length * 2;
  }
}

function safeUrl(rawUrl) {
  try {
    return rawUrl ? new URL(rawUrl) : null;
  } catch {
    return null;
  }
}

function classifyHost(value) {
  if (!value) return 'unknown';

  const ipv4 =
    /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/.test(value);

  const ipv6 = value.includes(':');
  const fqdn = value.includes('.') && !ipv4 && !ipv6;
  const hostname = !value.includes('.') && !ipv4 && !ipv6;

  if (ipv4) return 'ipv4';
  if (ipv6) return 'ipv6';
  if (fqdn) return 'fqdn';
  if (hostname) return 'hostname';
  return 'unknown';
}

function classifyIpScope(value) {
  if (!value) return 'unknown';

  if (value === '127.0.0.1' || value === '::1') return 'loopback';
  if (/^10\./.test(value)) return 'private';
  if (/^192\.168\./.test(value)) return 'private';
  if (/^172\.(1[6-9]|2\d|3[0-1])\./.test(value)) return 'private';
  if (/^169\.254\./.test(value)) return 'link_local';
  if (/^fc/i.test(value) || /^fd/i.test(value)) return 'private';
  if (/^fe80:/i.test(value)) return 'link_local';

  return 'public';
}

function urlMeta(rawUrl) {
  const parsed = safeUrl(rawUrl);

  if (!parsed) {
    return {
      raw: rawUrl || null,
      scheme: null,
      host: null,
      hostType: 'unknown',
      port: null,
      path: null,
      pathDepth: null,
      queryPresent: null,
      fragmentPresent: null
    };
  }

  const path = parsed.pathname || '/';
  const pathDepth = path.split('/').filter(Boolean).length;

  return {
    raw: parsed.href,
    scheme: parsed.protocol.replace(':', ''),
    host: parsed.hostname || null,
    hostType: classifyHost(parsed.hostname || null),
    port: parsed.port ? Number(parsed.port) : null,
    path,
    pathDepth,
    queryPresent: !!parsed.search,
    fragmentPresent: !!parsed.hash
  };
}

function getOrigin(rawUrl) {
  try {
    return rawUrl ? new URL(rawUrl).origin : null;
  } catch {
    return null;
  }
}

function relationshipToTopLevel(topLevelUrlMeta, targetUrlMeta) {
  const top = topLevelUrlMeta?.raw ? getOrigin(topLevelUrlMeta.raw) : null;
  const target = targetUrlMeta?.raw ? getOrigin(targetUrlMeta.raw) : null;
  if (!top || !target) return 'unknown';
  return top === target ? 'same-origin' : 'cross-origin';
}

async function getBatchIndex() {
  const data = await chrome.storage.local.get([STORAGE_KEYS.BATCH_INDEX]);
  return Array.isArray(data[STORAGE_KEYS.BATCH_INDEX]) ? data[STORAGE_KEYS.BATCH_INDEX] : [];
}

async function setBatchIndex(index) {
  await chrome.storage.local.set({
    [STORAGE_KEYS.BATCH_INDEX]: index
  });
}

async function removeOldestBatchesUntilWithinBudget(incomingBatchBytes = 0) {
  let index = await getBatchIndex();
  let totalEstimatedBytes = index.reduce((sum, item) => sum + (item.bytes || 0), 0);

  while (
    index.length >= STORAGE_LIMITS.MAX_BATCHES ||
    totalEstimatedBytes + incomingBatchBytes > STORAGE_LIMITS.MAX_TOTAL_BYTES_ESTIMATE
  ) {
    const oldest = index.shift();
    if (!oldest) break;

    await chrome.storage.local.remove(oldest.storageKey);
    totalEstimatedBytes -= oldest.bytes || 0;
  }

  await setBatchIndex(index);
}

function makeBatchEnvelope(events, options = {}) {
  return {
    schemaVersion: Recorder.schemaVersion,
    batchId: options.batchId || newBatchId(),
    parentBatchId: options.parentBatchId || null,
    splitDepth: options.splitDepth || 0,
    sensorId: Recorder.sensorId,
    sessionId: Recorder.sessionId,
    createdAt: options.createdAt || nowIso(),
    count: events.length,
    events
  };
}

function splitEventsIntoTwo(events) {
  const midpoint = Math.ceil(events.length / 2);
  return [events.slice(0, midpoint), events.slice(midpoint)];
}

function splitBatchEnvelope(batchEnvelope) {
  const [leftEvents, rightEvents] = splitEventsIntoTwo(batchEnvelope.events);

  return [
    makeBatchEnvelope(leftEvents, {
      parentBatchId: batchEnvelope.parentBatchId || batchEnvelope.batchId,
      splitDepth: (batchEnvelope.splitDepth || 0) + 1,
      createdAt: batchEnvelope.createdAt
    }),
    makeBatchEnvelope(rightEvents, {
      parentBatchId: batchEnvelope.parentBatchId || batchEnvelope.batchId,
      splitDepth: (batchEnvelope.splitDepth || 0) + 1,
      createdAt: batchEnvelope.createdAt
    })
  ];
}

async function persistSingleBatchEnvelope(batchEnvelope) {
  const storageKey = `forensics_batch_${batchEnvelope.batchId}`;
  const bytes = estimateBytes(batchEnvelope);

  await removeOldestBatchesUntilWithinBudget(bytes);

  await chrome.storage.local.set({
    [storageKey]: batchEnvelope
  });

  const index = await getBatchIndex();
  index.push({
    batchId: batchEnvelope.batchId,
    parentBatchId: batchEnvelope.parentBatchId || null,
    splitDepth: batchEnvelope.splitDepth || 0,
    storageKey,
    createdAt: batchEnvelope.createdAt,
    count: batchEnvelope.count,
    bytes,
    schemaVersion: batchEnvelope.schemaVersion,
    sessionId: batchEnvelope.sessionId
  });

  await setBatchIndex(index);
}

async function persistBatchEnvelope(batchEnvelope) {
  const bytes = estimateBytes(batchEnvelope);

  if (bytes <= STORAGE_LIMITS.MAX_BATCH_BYTES_ESTIMATE) {
    await persistSingleBatchEnvelope(batchEnvelope);
    return;
  }

  if (batchEnvelope.events.length <= 1) {
    console.warn('Single-event batch exceeds preferred size; attempting direct persist', {
      batchId: batchEnvelope.batchId,
      bytes
    });
    await persistSingleBatchEnvelope(batchEnvelope);
    return;
  }

  console.warn('Batch too large; splitting before persist', {
    batchId: batchEnvelope.batchId,
    bytes,
    count: batchEnvelope.count
  });

  const [leftBatch, rightBatch] = splitBatchEnvelope(batchEnvelope);

  await persistBatchEnvelope(leftBatch);
  await persistBatchEnvelope(rightBatch);
}

function getOrCreateTabState(tabId) {
  if (!Recorder.tabState.has(tabId)) {
    Recorder.tabState.set(tabId, {
      createdAtMs: nowMs(),
      updatedAtMs: nowMs(),
      activatedAtMs: null,
      lastKnownUrl: null,
      lastKnownTitle: null,
      lastNavigationAtMs: null,
      lastSnapshotAtMs: null,
      lastVisibilityState: null,
      lastPageFocus: null,
      lastPageEventType: null,
      lastPageEventAtMs: null,
      lastUserInteractionAtMs: null,
      lastHistoryMutationAtMs: null,
      lastIframeActivityAtMs: null,
      lastLoginSignalAtMs: null,
      lastRedirectChainId: null,
      lastRedirectAtMs: null
    });
  }

  return Recorder.tabState.get(tabId);
}

function updateTabState(tabId, patch) {
  if (tabId == null || tabId < 0) return;
  const state = getOrCreateTabState(tabId);
  Object.assign(state, patch, { updatedAtMs: nowMs() });
}

function msSince(ts) {
  return typeof ts === 'number' ? nowMs() - ts : null;
}

function buildInteractionContext(tabId) {
  if (tabId == null || tabId < 0 || !Recorder.tabState.has(tabId)) {
    return null;
  }

  const state = Recorder.tabState.get(tabId);
  return {
    msSinceTabCreated: msSince(state.createdAtMs),
    msSinceLastActivated: msSince(state.activatedAtMs),
    msSinceLastNavigation: msSince(state.lastNavigationAtMs),
    msSinceLastSnapshot: msSince(state.lastSnapshotAtMs),
    msSinceLastPageEvent: msSince(state.lastPageEventAtMs),
    msSinceLastUserInteraction: msSince(state.lastUserInteractionAtMs),
    msSinceLastHistoryMutation: msSince(state.lastHistoryMutationAtMs),
    msSinceLastIframeActivity: msSince(state.lastIframeActivityAtMs),
    msSinceLastLoginSignal: msSince(state.lastLoginSignalAtMs),
    msSinceLastRedirect: msSince(state.lastRedirectAtMs),
    lastVisibilityState: state.lastVisibilityState,
    lastPageFocus: state.lastPageFocus,
    lastKnownUrl: state.lastKnownUrl,
    lastKnownTitle: state.lastKnownTitle,
    lastPageEventType: state.lastPageEventType,
    lastRedirectChainId: state.lastRedirectChainId
  };
}

function inferProvenance(type, interactionContext = null) {
  if (type === 'request_redirect') {
    return { provenance: 'network_redirect', confidence: 'high' };
  }

  if (
    type.startsWith('extension_') ||
    type === 'runtime_installed' ||
    type === 'runtime_startup' ||
    type.startsWith('extension_inventory')
  ) {
    return { provenance: 'browser_automatic', confidence: 'high' };
  }

  if (type === 'page_event') {
    return { provenance: 'page_script', confidence: 'medium' };
  }

  if (
    interactionContext?.msSinceLastUserInteraction != null &&
    interactionContext.msSinceLastUserInteraction < 2000
  ) {
    return { provenance: 'user_interaction', confidence: 'medium' };
  }

  if (
    interactionContext?.msSinceLastHistoryMutation != null &&
    interactionContext.msSinceLastHistoryMutation < 1500
  ) {
    return { provenance: 'page_script', confidence: 'medium' };
  }

  if (interactionContext?.lastPageFocus === false) {
    return { provenance: 'browser_automatic', confidence: 'low' };
  }

  return { provenance: 'unknown', confidence: 'low' };
}

function deriveTags(type, data = {}, interactionContext = null) {
  const tags = [];

  if (type === 'request_redirect') tags.push('redirect');
  if (type === 'download_created') tags.push('download');
  if (type.startsWith('extension_')) tags.push('extension_posture_change');
  if (type === 'request_before_summary' || type === 'request_completed_summary') tags.push('summary');
  if (data.coalesced) tags.push('coalesced');

  if (type === 'extension_inventory_changed' || type === 'extension_inventory_snapshot') {
    tags.push('extension_inventory');
  }

  if (type === 'extension_enable_blocked' || type === 'extension_disabled_detected') {
    tags.push('extension_install_diagnostic');
  }

  if (data.resourceType === 'sub_frame') tags.push('subframe');
  if (data.resourceType === 'main_frame') tags.push('top_level_navigation');

  if (
    interactionContext?.msSinceLastLoginSignal != null &&
    interactionContext.msSinceLastLoginSignal < 10000
  ) {
    tags.push('recent_login_flow');
  }

  if (
    (type === 'navigation_committed' || type === 'request_redirect') &&
    (interactionContext?.msSinceLastUserInteraction == null ||
      interactionContext.msSinceLastUserInteraction > 5000)
  ) {
    tags.push('automatic_without_recent_user_interaction');
  }

  if (
    type === 'tab_removed' &&
    data.closeContext?.msSinceLastLoginSignal != null &&
    data.closeContext.msSinceLastLoginSignal < 10000
  ) {
    tags.push('tab_closed_soon_after_login_signal');
  }

  if (
    type === 'tab_removed' &&
    data.closeContext?.msSinceLastRedirect != null &&
    data.closeContext.msSinceLastRedirect < 5000
  ) {
    tags.push('tab_closed_soon_after_redirect');
  }

  return tags;
}

function eventFingerprint(type, data = {}) {
  return JSON.stringify({
    type,
    tabId: data.tabId ?? null,
    frameId: data.frameId ?? null,
    eventType: data.payload?.eventType ?? null,
    requestId: data.requestId ?? null,
    url: data.url?.raw ?? data.pageUrl?.raw ?? null,
    statusCode: data.statusCode ?? null
  });
}

function shouldSuppressDuplicate(type, data = {}) {
  const suppressible = new Set([
    'tab_updated',
    'navigation_reference_fragment_updated',
    'window_focus_changed'
  ]);

  if (!suppressible.has(type)) return false;

  const fingerprint = eventFingerprint(type, data);
  const previous = Recorder.recentEventFingerprints.get(fingerprint);
  const current = nowMs();

  Recorder.recentEventFingerprints.set(fingerprint, current);

  if (previous && current - previous < Recorder.dedupWindowMs) {
    return true;
  }

  if (Recorder.recentEventFingerprints.size > 2000) {
    for (const [key, value] of Recorder.recentEventFingerprints.entries()) {
      if (current - value > Recorder.dedupWindowMs * 5) {
        Recorder.recentEventFingerprints.delete(key);
      }
    }
  }

  return false;
}

function getOrCreateRedirectChain(requestId, tabId) {
  const key = `${tabId}:${requestId}`;
  if (!Recorder.redirectChains.has(key)) {
    Recorder.redirectChains.set(key, {
      chainId: crypto.randomUUID ? crypto.randomUUID() : `redir-${Date.now()}-${Math.random()}`,
      requestId,
      tabId,
      hopCount: 0,
      startedAt: nowIso()
    });
  }
  return Recorder.redirectChains.get(key);
}

function updateRedirectChainOnRedirect(d) {
  const chain = getOrCreateRedirectChain(d.requestId, d.tabId);
  chain.hopCount += 1;

  updateTabState(d.tabId, {
    lastRedirectChainId: chain.chainId,
    lastRedirectAtMs: nowMs()
  });

  return {
    redirectChainId: chain.chainId,
    redirectHopIndex: chain.hopCount,
    redirectHopCount: chain.hopCount
  };
}

function clearRedirectChain(requestId, tabId) {
  Recorder.redirectChains.delete(`${tabId}:${requestId}`);
}

function pageSnapshotFingerprint(snapshot) {
  if (!snapshot) return 'null';
  return JSON.stringify({
    url: snapshot.url || null,
    title: snapshot.title || null,
    visibilityState: snapshot.visibilityState || null,
    hasFocus: snapshot.hasFocus ?? null,
    iframeCount: snapshot.iframeCount ?? null,
    loginFormCount: snapshot.loginFormCount ?? null,
    iframes: Array.isArray(snapshot.iframes)
      ? snapshot.iframes.map((f) => ({
          src: f?.src?.raw || null,
          sameOrigin: f?.sameOrigin ?? null,
          hidden: f?.visibility?.hidden ?? null,
          sandbox: f?.sandbox || null
        }))
      : [],
    loginForms: Array.isArray(snapshot.loginForms)
      ? snapshot.loginForms.map((f) => ({
          action: f?.action?.raw || f?.action || null,
          method: f?.method || null,
          containsPasswordField: f?.containsPasswordField ?? null
        }))
      : []
  });
}

function shouldRecordPageSnapshot(tabId, snapshot) {
  const currentFingerprint = pageSnapshotFingerprint(snapshot);
  const previousFingerprint = Recorder.lastPageSnapshotFingerprintByTab.get(tabId);
  const previousAt = Recorder.lastPageSnapshotAtByTab.get(tabId) || 0;
  const currentAt = nowMs();

  const changed = currentFingerprint !== previousFingerprint;
  const agedOut = currentAt - previousAt >= Recorder.pageSnapshotMinIntervalMs;

  if (!changed && !agedOut) {
    return false;
  }

  Recorder.lastPageSnapshotFingerprintByTab.set(tabId, currentFingerprint);
  Recorder.lastPageSnapshotAtByTab.set(tabId, currentAt);
  return true;
}

function uniqueSorted(values) {
  return [...new Set(values.filter((value) => value != null))].sort();
}

function uniquePreserveOrder(values) {
  const seen = new Set();
  const result = [];

  for (const value of values) {
    const key = typeof value === 'string' ? value : JSON.stringify(value);
    if (value == null || seen.has(key)) continue;
    seen.add(key);
    result.push(value);
  }

  return result;
}

function safeHostnameFromUrlMeta(meta) {
  return meta?.host || null;
}

function safePathFromUrlMeta(meta) {
  return meta?.path || '/';
}

function firstPathSegments(path, maxSegments = 2) {
  const segments = String(path || '/')
    .split('/')
    .filter(Boolean)
    .slice(0, maxSegments);

  return '/' + segments.join('/');
}

function canonicalizePathForGrouping(path, resourceType) {
  const rawPath = String(path || '/');

  if (rawPath === '/') return '/';

  if (
    rawPath.endsWith('/favicon.ico') ||
    rawPath === '/favicon.ico' ||
    rawPath.endsWith('/robots.txt') ||
    rawPath === '/robots.txt' ||
    rawPath.endsWith('/px.gif') ||
    rawPath === '/px.gif'
  ) {
    return rawPath;
  }

  if (
    resourceType === 'xmlhttprequest' ||
    resourceType === 'fetch' ||
    resourceType === 'ping' ||
    resourceType === 'image' ||
    resourceType === 'script'
  ) {
    return firstPathSegments(rawPath, 2) || rawPath;
  }

  return rawPath;
}

function initiatorHostFromValue(initiator) {
  if (!initiator) return null;
  try {
    return new URL(initiator).hostname || null;
  } catch {
    return initiator;
  }
}

function canonicalizeRequestForGrouping(data) {
  const host = safeHostnameFromUrlMeta(data.url);
  const path = safePathFromUrlMeta(data.url);
  const canonicalPath = canonicalizePathForGrouping(path, data.resourceType);
  const initiatorHost = initiatorHostFromValue(data.initiator);

  return {
    tabId: data.tabId ?? null,
    method: data.method ?? null,
    resourceType: data.resourceType ?? null,
    host,
    canonicalPath,
    statusCode: data.statusCode ?? null,
    relationshipToTopLevel: data.relationshipToTopLevel ?? null,
    initiatorHost
  };
}

function buildRequestGroupKey(kind, data) {
  const canonical = canonicalizeRequestForGrouping(data);

  return JSON.stringify({
    kind,
    ...canonical
  });
}

function createRequestGroup(data) {
  const currentAt = nowMs();
  const canonical = canonicalizeRequestForGrouping(data);

  return {
    createdAtMs: currentAt,
    updatedAtMs: currentAt,
    firstTimestamp: nowIso(),
    lastTimestamp: nowIso(),
    template: {
      tabId: data.tabId ?? null,
      method: data.method ?? null,
      resourceType: data.resourceType ?? null,
      relationshipToTopLevel: data.relationshipToTopLevel ?? null,
      statusCode: data.statusCode ?? null,
      canonical: {
        host: canonical.host,
        canonicalPath: canonical.canonicalPath,
        initiatorHost: canonical.initiatorHost
      }
    },
    requestIds: [],
    frameIds: [],
    documentIds: [],
    remoteIps: [],
    remoteIpTypes: [],
    remoteIpScopes: [],
    fromCacheValues: [],
    statusLines: [],
    fullUrls: [],
    urlHits: new Map()
  };
}

function queueRequestSummary(kind, data) {
  const map = kind === 'before' ? Recorder.requestBeforeGroups : Recorder.requestCompletedGroups;
  const key = buildRequestGroupKey(kind, data);
  const currentAt = nowMs();
  const currentIso = nowIso();
  const fullUrl = data.url?.raw || null;

  let group = map.get(key);
  if (!group) {
    group = createRequestGroup(data);
    map.set(key, group);
  }

  group.updatedAtMs = currentAt;
  group.lastTimestamp = currentIso;
  group.requestIds.push(data.requestId);

  if (data.frameId != null) group.frameIds.push(data.frameId);
  if (data.documentId != null) group.documentIds.push(data.documentId);
  if (data.remoteIp != null) group.remoteIps.push(data.remoteIp);
  if (data.remoteIpType != null) group.remoteIpTypes.push(data.remoteIpType);
  if (data.remoteIpScope != null) group.remoteIpScopes.push(data.remoteIpScope);
  if (typeof data.fromCache === 'boolean') group.fromCacheValues.push(data.fromCache);
  if (data.statusLine != null) group.statusLines.push(data.statusLine);
  if (fullUrl != null) group.fullUrls.push(fullUrl);

  if (fullUrl != null) {
    const existing = group.urlHits.get(fullUrl);
    if (existing) {
      existing.lastSeenAt = currentIso;
      existing.count += 1;
      if (data.requestId != null) existing.requestIds.push(data.requestId);
    } else {
      group.urlHits.set(fullUrl, {
        url: fullUrl,
        firstSeenAt: currentIso,
        lastSeenAt: currentIso,
        count: 1,
        requestIds: data.requestId != null ? [data.requestId] : []
      });
    }
  }

  if (group.requestIds.length >= 10) {
    void flushRequestGroup(kind, key);
  }
}

function buildOccurrence(type, data = {}) {
  if (
    type === 'request_before' ||
    type === 'request_before_summary' ||
    type === 'request_completed' ||
    type === 'request_completed_summary'
  ) {
    return {
      requestId: data.requestId ?? null,
      requestIds: uniqueSorted(data.requestIds || []),
      frameIds: uniqueSorted(data.frameIds || []),
      documentIds: uniqueSorted(data.documentIds || []),
      fullUrls: uniquePreserveOrder(data.fullUrls || []),
      remoteIps: uniqueSorted(data.remoteIps || []),
      remoteIpTypes: uniqueSorted(data.remoteIpTypes || []),
      remoteIpScopes: uniqueSorted(data.remoteIpScopes || []),
      fromCacheValues: uniquePreserveOrder(data.fromCacheValues || []),
      statusLines: uniquePreserveOrder(data.statusLines || []),
      firstSeenAt: data.firstSeenAt || null,
      lastSeenAt: data.lastSeenAt || null,
      count: data.count || 1
    };
  }

  if (type === 'page_event') {
    return {
      eventType: data.payload?.eventType ?? null,
      pageUrl: data.pageUrl?.raw ?? null,
      timestamp: data.payload?.timestamp || null,
      payload: data.payload?.payload ?? null
    };
  }

  if (type === 'page_snapshot') {
    return {
      reason: data.reason ?? null,
      url: data.snapshot?.url ?? null,
      title: data.snapshot?.title ?? null,
      timestamp: data.snapshot?.timestamp || null
    };
  }

  return {
    timestamp: nowIso()
  };
}

function buildVariationSummary(data = {}) {
  return {
    requestIds: uniqueSorted(data.requestIds || []),
    frameIds: uniqueSorted(data.frameIds || []),
    documentIds: uniqueSorted(data.documentIds || []),
    fullUrls: uniquePreserveOrder(data.fullUrls || []),
    remoteIps: uniqueSorted(data.remoteIps || []),
    remoteIpTypes: uniqueSorted(data.remoteIpTypes || []),
    remoteIpScopes: uniqueSorted(data.remoteIpScopes || []),
    fromCacheValues: uniquePreserveOrder(data.fromCacheValues || []),
    statusLines: uniquePreserveOrder(data.statusLines || [])
  };
}

function mergeUrlHits(existingHits = [], incomingHits = []) {
  const map = new Map();

  for (const hit of [...existingHits, ...incomingHits]) {
    if (!hit?.url) continue;

    const current = map.get(hit.url);
    if (!current) {
      map.set(hit.url, {
        url: hit.url,
        firstSeenAt: hit.firstSeenAt || null,
        lastSeenAt: hit.lastSeenAt || null,
        count: hit.count || 0,
        requestIds: uniqueSorted(hit.requestIds || [])
      });
      continue;
    }

    current.firstSeenAt =
      [current.firstSeenAt, hit.firstSeenAt].filter(Boolean).sort()[0] || current.firstSeenAt;
    current.lastSeenAt =
      [current.lastSeenAt, hit.lastSeenAt].filter(Boolean).sort().slice(-1)[0] || current.lastSeenAt;
    current.count += hit.count || 0;
    current.requestIds = uniqueSorted([...(current.requestIds || []), ...(hit.requestIds || [])]);
  }

  return Array.from(map.values());
}

function mergeOccurrences(existing = [], incoming = []) {
  return [...existing, ...incoming];
}

function computeExtensionInventoryMetrics(inventory) {
  const metrics = {
    total: inventory.length,
    enabledCount: 0,
    disabledCount: 0,
    mayEnableFalseCount: 0,
    mayDisableFalseCount: 0,
    disabledReasonCounts: {},
    installTypeCounts: {},
    hostPermissionCountTotal: 0,
    permissionCountTotal: 0
  };

  for (const item of inventory) {
    if (item.enabled) metrics.enabledCount += 1;
    else metrics.disabledCount += 1;

    if (item.mayEnable === false) metrics.mayEnableFalseCount += 1;
    if (item.mayDisable === false) metrics.mayDisableFalseCount += 1;

    const disabledReason = item.disabledReason || 'none';
    metrics.disabledReasonCounts[disabledReason] =
      (metrics.disabledReasonCounts[disabledReason] || 0) + 1;

    const installType = item.installType || 'unknown';
    metrics.installTypeCounts[installType] =
      (metrics.installTypeCounts[installType] || 0) + 1;

    metrics.hostPermissionCountTotal += Array.isArray(item.hostPermissions)
      ? item.hostPermissions.length
      : 0;
    metrics.permissionCountTotal += Array.isArray(item.permissions)
      ? item.permissions.length
      : 0;
  }

  return metrics;
}

function extensionDiff(before, after) {
  const changes = {};
  const keys = [
    'enabled',
    'mayEnable',
    'mayDisable',
    'disabledReason',
    'version',
    'installType',
    'hostPermissions',
    'permissions',
    'name',
    'homepageUrl',
    'shortName'
  ];

  for (const key of keys) {
    const beforeValue = Array.isArray(before?.[key])
      ? [...before[key]].sort()
      : before?.[key] ?? null;
    const afterValue = Array.isArray(after?.[key])
      ? [...after[key]].sort()
      : after?.[key] ?? null;

    if (JSON.stringify(beforeValue) !== JSON.stringify(afterValue)) {
      changes[key] = {
        before: beforeValue,
        after: afterValue
      };
    }
  }

  return changes;
}

function buildExtensionInventoryDelta(previousInventory, currentInventory) {
  const previousById = new Map(previousInventory.map((item) => [item.id, item]));
  const currentById = new Map(currentInventory.map((item) => [item.id, item]));

  const added = [];
  const removed = [];
  const changed = [];

  for (const [id, item] of currentById.entries()) {
    if (!previousById.has(id)) {
      added.push(item);
      continue;
    }

    const diff = extensionDiff(previousById.get(id), item);
    if (Object.keys(diff).length) {
      changed.push({
        id,
        name: item.name || previousById.get(id)?.name || null,
        before: previousById.get(id),
        after: item,
        diff
      });
    }
  }

  for (const [id, item] of previousById.entries()) {
    if (!currentById.has(id)) {
      removed.push(item);
    }
  }

  return { added, removed, changed };
}

async function emitExtensionInstallDiagnostics(delta, inventory, reason) {
  for (const item of inventory) {
    if (!item.enabled) {
      await record('extension_disabled_detected', {
        reason,
        extension: item,
        diagnostic: {
          enabled: item.enabled,
          mayEnable: item.mayEnable ?? null,
          mayDisable: item.mayDisable ?? null,
          disabledReason: item.disabledReason || null,
          installType: item.installType || null
        }
      });
    }

    if (item.mayEnable === false) {
      await record('extension_enable_blocked', {
        reason,
        extension: item,
        diagnostic: {
          enabled: item.enabled,
          mayEnable: item.mayEnable ?? null,
          mayDisable: item.mayDisable ?? null,
          disabledReason: item.disabledReason || null,
          installType: item.installType || null
        }
      });
    }
  }

  for (const item of delta.added) {
    if (item.enabled === false || item.mayEnable === false) {
      await record('extension_install_posture_changed', {
        reason,
        changeKind: 'added_but_not_usable',
        extension: item,
        diagnostic: {
          enabled: item.enabled,
          mayEnable: item.mayEnable ?? null,
          mayDisable: item.mayDisable ?? null,
          disabledReason: item.disabledReason || null,
          installType: item.installType || null
        }
      });
    }
  }

  for (const change of delta.changed) {
    if (change.diff.enabled || change.diff.mayEnable || change.diff.disabledReason) {
      await record('extension_install_posture_changed', {
        reason,
        changeKind: 'state_changed',
        id: change.id,
        name: change.name,
        diff: change.diff,
        before: {
          enabled: change.before?.enabled ?? null,
          mayEnable: change.before?.mayEnable ?? null,
          mayDisable: change.before?.mayDisable ?? null,
          disabledReason: change.before?.disabledReason ?? null,
          installType: change.before?.installType ?? null
        },
        after: {
          enabled: change.after?.enabled ?? null,
          mayEnable: change.after?.mayEnable ?? null,
          mayDisable: change.after?.mayDisable ?? null,
          disabledReason: change.after?.disabledReason ?? null,
          installType: change.after?.installType ?? null
        }
      });
    }
  }
}

async function flushRequestGroup(kind, key) {
  const map = kind === 'before' ? Recorder.requestBeforeGroups : Recorder.requestCompletedGroups;
  const group = map.get(key);
  if (!group) return;

  map.delete(key);

  const count = group.requestIds.length;
  const urlHits = Array.from(group.urlHits.values()).map((entry) => ({
    url: entry.url,
    firstSeenAt: entry.firstSeenAt,
    lastSeenAt: entry.lastSeenAt,
    count: entry.count,
    requestIds: uniqueSorted(entry.requestIds)
  }));

  const payload = {
    ...group.template,
    count,
    requestIds: uniqueSorted(group.requestIds),
    frameIds: uniqueSorted(group.frameIds),
    documentIds: uniqueSorted(group.documentIds),
    firstSeenAt: group.firstTimestamp,
    lastSeenAt: group.lastTimestamp,
    fullUrls: uniquePreserveOrder(group.fullUrls),
    urlHits
  };

  if (group.remoteIps.length) payload.remoteIps = uniqueSorted(group.remoteIps);
  if (group.remoteIpTypes.length) payload.remoteIpTypes = uniqueSorted(group.remoteIpTypes);
  if (group.remoteIpScopes.length) payload.remoteIpScopes = uniqueSorted(group.remoteIpScopes);
  if (group.fromCacheValues.length) payload.fromCacheValues = uniquePreserveOrder(group.fromCacheValues);
  if (group.statusLines.length) payload.statusLines = uniquePreserveOrder(group.statusLines);

  payload.variationSummary = buildVariationSummary(payload);
  payload.occurrences = [buildOccurrence(kind === 'before' ? 'request_before_summary' : 'request_completed_summary', payload)];

  const isImportantSingleton =
    payload.resourceType === 'main_frame' ||
    payload.resourceType === 'sub_frame';

  if (count > 1) {
    const summaryType = kind === 'before' ? 'request_before_summary' : 'request_completed_summary';
    await record(summaryType, payload);
    return;
  }

  if (kind === 'before' && !isImportantSingleton) {
    return;
  }

  const singleType = kind === 'before' ? 'request_before' : 'request_completed';
  await record(singleType, {
    ...payload,
    requestId: payload.requestIds[0] || null
  });
}

async function flushExpiredRequestGroups() {
  const currentAt = nowMs();

  for (const [key, group] of Recorder.requestBeforeGroups.entries()) {
    if (currentAt - group.updatedAtMs >= Recorder.requestGroupWindowMs) {
      await flushRequestGroup('before', key);
    }
  }

  for (const [key, group] of Recorder.requestCompletedGroups.entries()) {
    if (currentAt - group.updatedAtMs >= Recorder.requestGroupWindowMs) {
      await flushRequestGroup('completed', key);
    }
  }
}

function stableSortObject(value) {
  if (Array.isArray(value)) {
    return value.map(stableSortObject);
  }

  if (value && typeof value === 'object') {
    return Object.keys(value)
      .sort()
      .reduce((acc, key) => {
        acc[key] = stableSortObject(value[key]);
        return acc;
      }, {});
  }

  return value;
}

function normalizedCoalescingType(type) {
  if (type === 'request_before' || type === 'request_before_summary') {
    return 'request_before_summary';
  }

  if (type === 'request_completed' || type === 'request_completed_summary') {
    return 'request_completed_summary';
  }

  return type;
}

function canonicalizeForCoalescing(type, data = {}) {
  const normalizedType = normalizedCoalescingType(type);

  if (
    normalizedType === 'request_before_summary' ||
    normalizedType === 'request_completed_summary'
  ) {
    return stableSortObject({
      type: normalizedType,
      tabId: data.tabId ?? null,
      method: data.method ?? null,
      resourceType: data.resourceType ?? null,
      relationshipToTopLevel: data.relationshipToTopLevel ?? null,
      statusCode: data.statusCode ?? null,
      canonical: {
        host: data.canonical?.host ?? null,
        canonicalPath: data.canonical?.canonicalPath ?? null,
        initiatorHost: data.canonical?.initiatorHost ?? null
      }
    });
  }

  if (type === 'page_snapshot') {
    return stableSortObject({
      type,
      tabId: data.tabId ?? null,
      snapshot: {
        url: data.snapshot?.url ?? null,
        title: data.snapshot?.title ?? null,
        visibilityState: data.snapshot?.visibilityState ?? null,
        hasFocus: data.snapshot?.hasFocus ?? null,
        iframeCount: data.snapshot?.iframeCount ?? null,
        loginFormCount: data.snapshot?.loginFormCount ?? null
      }
    });
  }

  if (type === 'page_event') {
    const eventType = data.payload?.eventType ?? null;
    const pageUrl = data.pageUrl?.raw ?? null;
    const nested = data.payload?.payload ?? {};

    if (eventType === 'iframe_attribute_changed') {
      return stableSortObject({
        type,
        tabId: data.tabId ?? null,
        frameId: data.frameId ?? null,
        eventType,
        pageUrl,
        attribute: nested.attribute ?? null,
        iframeSrcHost: nested.frame?.src?.host ?? null
      });
    }

    if (eventType === 'iframe_added') {
      return stableSortObject({
        type,
        tabId: data.tabId ?? null,
        frameId: data.frameId ?? null,
        eventType,
        pageUrl,
        iframeSrcHost: nested.frame?.src?.host ?? null,
        iframeSandbox: nested.frame?.sandbox ?? null
      });
    }

    if (eventType === 'login_form_detected') {
      return stableSortObject({
        type,
        tabId: data.tabId ?? null,
        frameId: data.frameId ?? null,
        eventType,
        pageUrl,
        count: nested.count ?? null
      });
    }

    if (eventType === 'visibility_change') {
      return stableSortObject({
        type,
        tabId: data.tabId ?? null,
        frameId: data.frameId ?? null,
        eventType,
        pageUrl,
        visibilityState: nested.visibilityState ?? null,
        hasFocus: nested.hasFocus ?? null
      });
    }

    if (
      eventType === 'user_interaction_click' ||
      eventType === 'user_interaction_submit' ||
      eventType === 'window_focus' ||
      eventType === 'window_blur' ||
      eventType === 'page_hide' ||
      eventType === 'before_unload' ||
      eventType === 'history_push_state' ||
      eventType === 'history_replace_state' ||
      eventType === 'history_popstate'
    ) {
      return stableSortObject({
        type,
        tabId: data.tabId ?? null,
        frameId: data.frameId ?? null,
        eventType,
        pageUrl
      });
    }

    if (
      eventType === 'page_fcp' ||
      eventType === 'page_lcp_candidate' ||
      eventType === 'page_lcp' ||
      eventType === 'page_cls' ||
      eventType === 'page_nav_timing' ||
      eventType === 'page_perf_summary' ||
      eventType === 'extension_perf_measurement'
    ) {
      return stableSortObject({
        type,
        tabId: data.tabId ?? null,
        frameId: data.frameId ?? null,
        eventType,
        pageUrl,
        metricName: nested.name ?? null,
        reason: nested.reason ?? null
      });
    }

    return stableSortObject({
      type,
      tabId: data.tabId ?? null,
      frameId: data.frameId ?? null,
      eventType,
      pageUrl
    });
  }

  return stableSortObject({ type, data });
}

function canCoalesceEvent(type) {
  return new Set([
    'request_before',
    'request_before_summary',
    'request_completed',
    'request_completed_summary',
    'page_snapshot',
    'page_event'
  ]).has(type);
}

function mergedEventTypeForCoalescing(type) {
  const normalizedType = normalizedCoalescingType(type);

  if (
    normalizedType === 'request_before_summary' ||
    normalizedType === 'request_completed_summary'
  ) {
    return normalizedType;
  }

  return type;
}

function mergeCoalescedData(existingData = {}, incomingData = {}, type = null) {
  const merged = {
    ...existingData,
    ...incomingData
  };

  merged.count = (existingData.count || 0) + (incomingData.count || 0);
  merged.repeatCount = (existingData.repeatCount || 1) + (incomingData.repeatCount || 1);
  merged.lastCoalescedAt = nowIso();
  merged.coalesced = true;

  if (
    type === 'request_before' ||
    type === 'request_before_summary' ||
    type === 'request_completed' ||
    type === 'request_completed_summary'
  ) {
    merged.requestIds = uniqueSorted([
      ...(existingData.requestIds || []),
      ...(incomingData.requestIds || [])
    ]);

    merged.frameIds = uniqueSorted([
      ...(existingData.frameIds || []),
      ...(incomingData.frameIds || [])
    ]);

    merged.documentIds = uniqueSorted([
      ...(existingData.documentIds || []),
      ...(incomingData.documentIds || [])
    ]);

    merged.remoteIps = uniqueSorted([
      ...(existingData.remoteIps || []),
      ...(incomingData.remoteIps || [])
    ]);

    merged.remoteIpTypes = uniqueSorted([
      ...(existingData.remoteIpTypes || []),
      ...(incomingData.remoteIpTypes || [])
    ]);

    merged.remoteIpScopes = uniqueSorted([
      ...(existingData.remoteIpScopes || []),
      ...(incomingData.remoteIpScopes || [])
    ]);

    merged.fromCacheValues = uniquePreserveOrder([
      ...(existingData.fromCacheValues || []),
      ...(incomingData.fromCacheValues || [])
    ]);

    merged.statusLines = uniquePreserveOrder([
      ...(existingData.statusLines || []),
      ...(incomingData.statusLines || [])
    ]);

    merged.fullUrls = uniquePreserveOrder([
      ...(existingData.fullUrls || []),
      ...(incomingData.fullUrls || [])
    ]);

    merged.urlHits = mergeUrlHits(existingData.urlHits || [], incomingData.urlHits || []);

    const firstSeenCandidates = [
      existingData.firstSeenAt,
      incomingData.firstSeenAt
    ].filter(Boolean).sort();

    const lastSeenCandidates = [
      existingData.lastSeenAt,
      incomingData.lastSeenAt
    ].filter(Boolean).sort();

    if (firstSeenCandidates.length) merged.firstSeenAt = firstSeenCandidates[0];
    if (lastSeenCandidates.length) merged.lastSeenAt = lastSeenCandidates[lastSeenCandidates.length - 1];

    if (existingData.canonical || incomingData.canonical) {
      merged.canonical = {
        ...(existingData.canonical || {}),
        ...(incomingData.canonical || {})
      };
    }

    merged.variationSummary = buildVariationSummary(merged);
  }

  const existingOccurrences = existingData.occurrences || [buildOccurrence(type, existingData)];
  const incomingOccurrences = incomingData.occurrences || [buildOccurrence(type, incomingData)];
  merged.occurrences = mergeOccurrences(existingOccurrences, incomingOccurrences);

  if (type === 'page_event') {
    merged.variationSummary = {
      eventType: merged.payload?.eventType ?? null,
      pageUrl: merged.pageUrl?.raw ?? null,
      occurrenceCount: merged.occurrences.length,
      distinctPayloads: uniquePreserveOrder(
        merged.occurrences.map((occurrence) => occurrence.payload ?? null)
      )
    };
  }

  return merged;
}

function tryCoalesceQueuedEvent(type, data) {
  if (!canCoalesceEvent(type) || !Recorder.queue.length) {
    return false;
  }

  const canonicalKey = JSON.stringify(canonicalizeForCoalescing(type, data));
  const currentAt = nowMs();
  const recent = Recorder.recentCoalescedEvents.get(canonicalKey);

  if (!recent) {
    return false;
  }

  if (currentAt - recent.lastSeenMs > Recorder.coalesceWindowMs) {
    Recorder.recentCoalescedEvents.delete(canonicalKey);
    return false;
  }

  const queuedEvent = Recorder.queue[recent.queueIndex];
  if (!queuedEvent) {
    Recorder.recentCoalescedEvents.delete(canonicalKey);
    return false;
  }

  const queuedCanonicalKey = JSON.stringify(
    canonicalizeForCoalescing(queuedEvent.type, queuedEvent.data)
  );

  if (queuedCanonicalKey !== canonicalKey) {
    Recorder.recentCoalescedEvents.delete(canonicalKey);
    return false;
  }

  queuedEvent.data = mergeCoalescedData(queuedEvent.data, data, queuedEvent.type);
  queuedEvent.type = mergedEventTypeForCoalescing(queuedEvent.type);
  queuedEvent.tags = Array.from(new Set([...(queuedEvent.tags || []), 'summary', 'coalesced']));

  recent.lastSeenMs = currentAt;
  return true;
}

function rememberCoalescibleEvent(type, data) {
  if (!canCoalesceEvent(type)) return;

  const canonicalKey = JSON.stringify(canonicalizeForCoalescing(type, data));
  Recorder.recentCoalescedEvents.set(canonicalKey, {
    queueIndex: Recorder.queue.length - 1,
    lastSeenMs: nowMs()
  });

  if (Recorder.recentCoalescedEvents.size > 2000) {
    for (const [key, value] of Recorder.recentCoalescedEvents.entries()) {
      if (nowMs() - value.lastSeenMs > Recorder.coalesceWindowMs * 4) {
        Recorder.recentCoalescedEvents.delete(key);
      }
    }
  }
}

async function buildEvent(type, data = {}) {
  const tabId = data.tabId ?? null;
  const interactionContext = buildInteractionContext(tabId);
  const { provenance, confidence } = inferProvenance(type, interactionContext);
  const tags = deriveTags(type, data, interactionContext);

  const event = {
    schemaVersion: Recorder.schemaVersion,
    seq: ++Recorder.seq,
    sensorId: Recorder.sensorId,
    sessionId: Recorder.sessionId,
    timestamp: nowIso(),
    monotonicMs: monotonicMs(),
    type,
    extensionVersion: chrome.runtime.getManifest?.().version || null,
    provenance,
    confidence,
    tags,
    interactionContext,
    data
  };

  const canonical = JSON.stringify({
    schemaVersion: event.schemaVersion,
    seq: event.seq,
    sensorId: event.sensorId,
    sessionId: event.sessionId,
    timestamp: event.timestamp,
    monotonicMs: event.monotonicMs,
    type: event.type,
    provenance: event.provenance,
    confidence: event.confidence,
    tags: event.tags,
    interactionContext: event.interactionContext,
    data: event.data,
    previousEventHash: Recorder.previousEventHash
  });

  const eventHash = await sha256Hex(canonical);

  event.integrity = {
    previousEventHash: Recorder.previousEventHash,
    eventHash
  };

  Recorder.previousEventHash = eventHash;
  return event;
}

async function record(type, data = {}) {
  try {
    if (shouldSuppressDuplicate(type, data)) return;

    if (tryCoalesceQueuedEvent(type, data)) {
      return;
    }

    const event = await buildEvent(type, data);
    Recorder.queue.push(event);
    rememberCoalescibleEvent(type, data);

    if (Recorder.queue.length >= Recorder.maxQueueSize) {
      await flush();
    }
  } catch (err) {
    console.error('record() failed', err);
  }
}

async function flush() {
  await flushExpiredRequestGroups();

  if (!Recorder.queue.length) return;

  const batch = Recorder.queue.splice(0, Recorder.queue.length);
  Recorder.recentCoalescedEvents.clear();

  const batchEnvelope = makeBatchEnvelope(batch);

  try {
    await persistBatchEnvelope(batchEnvelope);
  } catch (err) {
    console.error('Failed to persist forensics batch', err);

    try {
      const bytesInUse = await chrome.storage.local.getBytesInUse(null);
      console.error('storage.local bytes currently in use:', bytesInUse);
    } catch (_) {}
  }

  console.log('[ForensicsBatch]', {
    batchId: batchEnvelope.batchId,
    count: batchEnvelope.count,
    createdAt: batchEnvelope.createdAt
  });
}

function normalizeExtensionInfo(info) {
  return {
    id: info.id || null,
    name: info.name || null,
    shortName: info.shortName || null,
    version: info.version || null,
    enabled: !!info.enabled,
    mayEnable: info.mayEnable ?? null,
    mayDisable: info.mayDisable ?? null,
    installType: info.installType || null,
    type: info.type || null,
    disabledReason: info.disabledReason || null,
    homepageUrl: info.homepageUrl || null,
    hostPermissions: Array.isArray(info.hostPermissions) ? info.hostPermissions : [],
    permissions: Array.isArray(info.permissions) ? info.permissions : []
  };
}

async function getExtensionInventory() {
  if (!chrome.management?.getAll) return [];

  const all = await chrome.management.getAll();
  return all
    .filter((item) => item.type === 'extension')
    .map(normalizeExtensionInfo)
    .sort((a, b) => (a.id || '').localeCompare(b.id || ''));
}

async function recordExtensionInventorySnapshot(reason = 'periodic') {
  try {
    const inventory = await getExtensionInventory();
    const inventoryHash = await sha256Hex(JSON.stringify(inventory));
    const previousInventory = Array.from(Recorder.lastExtensionInventoryById.values());
    const metrics = computeExtensionInventoryMetrics(inventory);

    if (reason === 'periodic' && inventoryHash === Recorder.lastExtensionInventoryHash) {
      return;
    }

    const previousHash = Recorder.lastExtensionInventoryHash;
    const delta = buildExtensionInventoryDelta(previousInventory, inventory);

    Recorder.lastExtensionInventoryHash = inventoryHash;
    Recorder.lastExtensionInventoryById = new Map(inventory.map((item) => [item.id, item]));

    await record(previousHash ? 'extension_inventory_changed' : 'extension_inventory_snapshot', {
      reason,
      inventoryHash,
      previousInventoryHash: previousHash,
      count: inventory.length,
      metrics,
      deltaSummary: {
        addedCount: delta.added.length,
        removedCount: delta.removed.length,
        changedCount: delta.changed.length
      },
      inventory
    });

    if (previousHash) {
      await record('extension_inventory_delta', {
        reason,
        inventoryHash,
        previousInventoryHash: previousHash,
        metrics,
        delta
      });
    }

    await emitExtensionInstallDiagnostics(delta, inventory, reason);
  } catch (err) {
    await record('extension_inventory_error', {
      reason,
      error: err?.message || String(err)
    });
  }
}

function requestSnapshot(tabId, reason) {
  chrome.tabs.sendMessage(
    tabId,
    { type: 'GET_PAGE_SNAPSHOT', reason },
    async (response) => {
      if (chrome.runtime.lastError) {
        await record('snapshot_unavailable', {
          tabId,
          reason,
          error: chrome.runtime.lastError.message
        });
        return;
      }

      updateTabState(tabId, {
        lastSnapshotAtMs: nowMs()
      });

      if (!shouldRecordPageSnapshot(tabId, response || null)) {
        return;
      }

      await record('page_snapshot', {
        tabId,
        reason,
        snapshot: response || null
      });
    }
  );
}

async function getAllForensicsStorage() {
  const all = await chrome.storage.local.get(null);
  return Object.fromEntries(
    Object.entries(all).filter(([key]) =>
      key === STORAGE_KEYS.SENSOR_ID ||
      key === STORAGE_KEYS.BATCH_INDEX ||
      key.startsWith('forensics_batch_')
    )
  );
}

async function getAllForensicsEvents() {
  const { [STORAGE_KEYS.BATCH_INDEX]: batchIndex = [] } =
    await chrome.storage.local.get([STORAGE_KEYS.BATCH_INDEX]);

  const keys = batchIndex.map((item) => item.storageKey);

  if (!keys.length) {
    return {
      sensorId: Recorder.sensorId,
      batchCount: 0,
      eventCount: 0,
      batches: [],
      events: []
    };
  }

  const stored = await chrome.storage.local.get(keys);
  const batches = batchIndex
    .map((meta) => stored[meta.storageKey])
    .filter(Boolean);

  const events = batches.flatMap((batch) => batch.events || []);

  return {
    sensorId: Recorder.sensorId,
    batchCount: batches.length,
    eventCount: events.length,
    batches,
    events
  };
}

async function dumpAllForensicsStorage() {
  const data = await getAllForensicsStorage();
  console.log('[ForensicsStorageDump]', data);
  return data;
}

async function dumpAllForensicsEvents() {
  const data = await getAllForensicsEvents();
  console.log('[ForensicsEventsDump]', data);
  return data;
}

async function dumpLatestBatch() {
  const { [STORAGE_KEYS.BATCH_INDEX]: batchIndex = [] } =
    await chrome.storage.local.get([STORAGE_KEYS.BATCH_INDEX]);

  if (!batchIndex.length) {
    console.log('[ForensicsLatestBatch] none');
    return null;
  }

  const latest = batchIndex[batchIndex.length - 1];
  const stored = await chrome.storage.local.get([latest.storageKey]);
  const batch = stored[latest.storageKey] || null;

  console.log('[ForensicsLatestBatch]', batch);
  return batch;
}

async function dumpEventsByType(type) {
  const { events } = await getAllForensicsEvents();
  const filtered = events.filter((event) => event.type === type);
  console.log(`[ForensicsEventsByType:${type}]`, filtered);
  return filtered;
}

async function dumpPerfEvents() {
  const { events } = await getAllForensicsEvents();
  const filtered = events.filter(
    (event) =>
      event.type === 'page_event' &&
      [
        'page_fcp',
        'page_lcp_candidate',
        'page_lcp',
        'page_cls',
        'page_nav_timing',
        'page_perf_summary',
        'extension_perf_measurement',
        'extension_perf_observer_error'
      ].includes(event.data?.payload?.eventType)
  );
  console.log('[ForensicsPerfEvents]', filtered);
  return filtered;
}

async function dumpExtensionDiagnostics() {
  const { events } = await getAllForensicsEvents();
  const filtered = events.filter((event) =>
    [
      'extension_inventory_snapshot',
      'extension_inventory_changed',
      'extension_inventory_delta',
      'extension_disabled_detected',
      'extension_enable_blocked',
      'extension_install_posture_changed',
      'extension_inventory_error',
      'extension_installed',
      'extension_enabled',
      'extension_disabled',
      'extension_uninstalled'
    ].includes(event.type)
  );
  console.log('[ForensicsExtensionDiagnostics]', filtered);
  return filtered;
}

async function exportForensicsEventsJson(pretty = true) {
  const data = await getAllForensicsEvents();
  const json = JSON.stringify(data, null, pretty ? 2 : 0);
  console.log(json);
  return json;
}

async function downloadForensicsEventsJson() {
  const data = await getAllForensicsEvents();
  const json = JSON.stringify(data, null, 2);
  const blob = new Blob([json], { type: 'application/json' });
  const url = URL.createObjectURL(blob);

  try {
    const downloadId = await chrome.downloads.download({
      url,
      filename: `forensics-export-${new Date().toISOString().replace(/[:.]/g, '-')}.json`,
      saveAs: true
    });

    console.log('[ForensicsDownloadStarted]', { downloadId });
    return downloadId;
  } finally {
    setTimeout(() => URL.revokeObjectURL(url), 60000);
  }
}

globalThis.forensicsDebug = {
  getAllForensicsStorage,
  getAllForensicsEvents,
  dumpAllForensicsStorage,
  dumpAllForensicsEvents,
  dumpLatestBatch,
  dumpEventsByType,
  dumpPerfEvents,
  dumpExtensionDiagnostics,
  exportForensicsEventsJson,
  downloadForensicsEventsJson
};

chrome.runtime.onInstalled?.addListener((details) => {
  void record('runtime_installed', {
    reason: details.reason || null,
    previousVersion: details.previousVersion || null
  });

  void recordExtensionInventorySnapshot('runtime_installed');
});

chrome.runtime.onStartup?.addListener(() => {
  void record('runtime_startup');
  void recordExtensionInventorySnapshot('runtime_startup');
});

chrome.tabs.onCreated.addListener((tab) => {
  if (tab.id != null) {
    updateTabState(tab.id, {
      createdAtMs: nowMs(),
      lastKnownUrl: urlMeta(tab.url || tab.pendingUrl || null),
      lastKnownTitle: tab.title || null
    });
  }

  void record('tab_created', {
    tabId: tab.id ?? null,
    windowId: tab.windowId ?? null,
    openerTabId: tab.openerTabId ?? null,
    active: !!tab.active,
    pinned: !!tab.pinned,
    audible: !!tab.audible,
    discarded: !!tab.discarded,
    status: tab.status || null,
    title: tab.title || null,
    url: urlMeta(tab.url || tab.pendingUrl || null)
  });
});

chrome.tabs.onActivated.addListener((info) => {
  updateTabState(info.tabId, {
    activatedAtMs: nowMs()
  });

  void record('tab_activated', {
    tabId: info.tabId,
    windowId: info.windowId
  });

  requestSnapshot(info.tabId, 'tab_activated');
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  updateTabState(tabId, {
    lastKnownUrl: urlMeta(changeInfo.url || tab.url || null),
    lastKnownTitle: changeInfo.title || tab.title || null
  });

  void record('tab_updated', {
    tabId,
    windowId: tab.windowId ?? null,
    status: changeInfo.status || tab.status || null,
    title: changeInfo.title || tab.title || null,
    url: urlMeta(changeInfo.url || tab.url || null)
  });

  if (changeInfo.status === 'complete') {
    requestSnapshot(tabId, 'tab_updated_complete');
  }
});

chrome.tabs.onRemoved.addListener((tabId, removeInfo) => {
  const state = Recorder.tabState.get(tabId) || null;
  const closeContext = state ? {
    tabLifetimeMs: msSince(state.createdAtMs),
    msSinceLastActivated: msSince(state.activatedAtMs),
    msSinceLastNavigation: msSince(state.lastNavigationAtMs),
    msSinceLastSnapshot: msSince(state.lastSnapshotAtMs),
    msSinceLastUserInteraction: msSince(state.lastUserInteractionAtMs),
    msSinceLastHistoryMutation: msSince(state.lastHistoryMutationAtMs),
    msSinceLastIframeActivity: msSince(state.lastIframeActivityAtMs),
    msSinceLastLoginSignal: msSince(state.lastLoginSignalAtMs),
    msSinceLastRedirect: msSince(state.lastRedirectAtMs),
    lastKnownUrl: state.lastKnownUrl,
    lastKnownTitle: state.lastKnownTitle,
    lastVisibilityState: state.lastVisibilityState,
    lastPageFocus: state.lastPageFocus,
    lastPageEventType: state.lastPageEventType,
    lastRedirectChainId: state.lastRedirectChainId
  } : null;

  void record('tab_removed', {
    tabId,
    windowId: removeInfo.windowId ?? null,
    isWindowClosing: !!removeInfo.isWindowClosing,
    closeContext
  });

  Recorder.tabState.delete(tabId);
  Recorder.lastPageSnapshotFingerprintByTab.delete(tabId);
  Recorder.lastPageSnapshotAtByTab.delete(tabId);
});

chrome.windows.onCreated.addListener((win) => {
  void record('window_created', {
    windowId: win.id ?? null,
    focused: !!win.focused,
    incognito: !!win.incognito,
    type: win.type || null,
    state: win.state || null,
    width: win.width ?? null,
    height: win.height ?? null
  });
});

chrome.windows.onFocusChanged.addListener((windowId) => {
  void record('window_focus_changed', { windowId });
});

chrome.windows.onRemoved.addListener((windowId) => {
  void record('window_removed', { windowId });
});

if (chrome.webNavigation) {
  chrome.webNavigation.onBeforeNavigate.addListener((d) => {
    updateTabState(d.tabId, {
      lastNavigationAtMs: nowMs(),
      lastKnownUrl: urlMeta(d.url)
    });

    void record('navigation_before', {
      tabId: d.tabId,
      frameId: d.frameId,
      parentFrameId: d.parentFrameId,
      documentId: d.documentId || null,
      documentLifecycle: d.documentLifecycle || null,
      url: urlMeta(d.url)
    });
  });

  chrome.webNavigation.onCommitted.addListener((d) => {
    updateTabState(d.tabId, {
      lastNavigationAtMs: nowMs(),
      lastKnownUrl: urlMeta(d.url)
    });

    void record('navigation_committed', {
      tabId: d.tabId,
      frameId: d.frameId,
      parentFrameId: d.parentFrameId,
      documentId: d.documentId || null,
      documentLifecycle: d.documentLifecycle || null,
      transitionType: d.transitionType || null,
      transitionQualifiers: d.transitionQualifiers || [],
      url: urlMeta(d.url)
    });

    if (d.frameId === 0) {
      requestSnapshot(d.tabId, 'navigation_committed');
    }
  });

  chrome.webNavigation.onDOMContentLoaded.addListener((d) => {
    void record('navigation_dom_content_loaded', {
      tabId: d.tabId,
      frameId: d.frameId,
      documentId: d.documentId || null,
      url: urlMeta(d.url)
    });
  });

  chrome.webNavigation.onCompleted.addListener((d) => {
    updateTabState(d.tabId, {
      lastNavigationAtMs: nowMs(),
      lastKnownUrl: urlMeta(d.url)
    });

    void record('navigation_completed', {
      tabId: d.tabId,
      frameId: d.frameId,
      documentId: d.documentId || null,
      url: urlMeta(d.url)
    });

    if (d.frameId === 0) {
      requestSnapshot(d.tabId, 'navigation_completed');
    }
  });

  chrome.webNavigation.onHistoryStateUpdated?.addListener((d) => {
    updateTabState(d.tabId, {
      lastNavigationAtMs: nowMs(),
      lastKnownUrl: urlMeta(d.url)
    });

    void record('navigation_history_state_updated', {
      tabId: d.tabId,
      frameId: d.frameId,
      documentId: d.documentId || null,
      transitionType: d.transitionType || null,
      transitionQualifiers: d.transitionQualifiers || [],
      url: urlMeta(d.url)
    });

    if (d.frameId === 0) {
      requestSnapshot(d.tabId, 'history_state_updated');
    }
  });

  chrome.webNavigation.onReferenceFragmentUpdated?.addListener((d) => {
    void record('navigation_reference_fragment_updated', {
      tabId: d.tabId,
      frameId: d.frameId,
      documentId: d.documentId || null,
      url: urlMeta(d.url)
    });
  });

  chrome.webNavigation.onErrorOccurred.addListener((d) => {
    void record('navigation_error', {
      tabId: d.tabId,
      frameId: d.frameId,
      documentId: d.documentId || null,
      error: d.error || null,
      url: urlMeta(d.url)
    });
  });
}

if (chrome.webRequest) {
  chrome.webRequest.onBeforeRequest.addListener(
    (d) => {
      const topLevel = Recorder.tabState.get(d.tabId)?.lastKnownUrl || null;
      const target = urlMeta(d.url);

      queueRequestSummary('before', {
        tabId: d.tabId,
        requestId: d.requestId,
        frameId: d.frameId,
        documentId: d.documentId || null,
        method: d.method,
        resourceType: d.type,
        initiator: d.initiator || null,
        url: target,
        relationshipToTopLevel: relationshipToTopLevel(topLevel, target)
      });
    },
    { urls: ['<all_urls>'] }
  );

  chrome.webRequest.onBeforeRedirect.addListener(
    (d) => {
      const topLevel = Recorder.tabState.get(d.tabId)?.lastKnownUrl || null;
      const redirectMeta = updateRedirectChainOnRedirect(d);

      void record('request_redirect', {
        tabId: d.tabId,
        requestId: d.requestId,
        frameId: d.frameId,
        documentId: d.documentId || null,
        method: d.method,
        resourceType: d.type,
        statusCode: d.statusCode,
        remoteIp: d.ip || null,
        remoteIpType: classifyHost(d.ip || null),
        remoteIpScope: classifyIpScope(d.ip || null),
        initiator: d.initiator || null,
        fromUrl: urlMeta(d.url),
        toUrl: urlMeta(d.redirectUrl),
        relationshipToTopLevel: relationshipToTopLevel(topLevel, urlMeta(d.redirectUrl)),
        ...redirectMeta
      });

      if (d.tabId >= 0) {
        requestSnapshot(d.tabId, 'request_redirect');
      }
    },
    { urls: ['<all_urls>'] }
  );

  chrome.webRequest.onCompleted.addListener(
    (d) => {
      const topLevel = Recorder.tabState.get(d.tabId)?.lastKnownUrl || null;
      const target = urlMeta(d.url);

      queueRequestSummary('completed', {
        tabId: d.tabId,
        requestId: d.requestId,
        frameId: d.frameId,
        documentId: d.documentId || null,
        method: d.method,
        resourceType: d.type,
        statusCode: d.statusCode,
        statusLine: d.statusLine || null,
        remoteIp: d.ip || null,
        remoteIpType: classifyHost(d.ip || null),
        remoteIpScope: classifyIpScope(d.ip || null),
        fromCache: !!d.fromCache,
        initiator: d.initiator || null,
        url: target,
        relationshipToTopLevel: relationshipToTopLevel(topLevel, target)
      });

      clearRedirectChain(d.requestId, d.tabId);
    },
    { urls: ['<all_urls>'] }
  );

  chrome.webRequest.onErrorOccurred.addListener(
    (d) => {
      const topLevel = Recorder.tabState.get(d.tabId)?.lastKnownUrl || null;
      const target = urlMeta(d.url);

      void record('request_error', {
        tabId: d.tabId,
        requestId: d.requestId,
        frameId: d.frameId,
        documentId: d.documentId || null,
        method: d.method,
        resourceType: d.type,
        error: d.error || null,
        initiator: d.initiator || null,
        url: target,
        relationshipToTopLevel: relationshipToTopLevel(topLevel, target)
      });

      clearRedirectChain(d.requestId, d.tabId);
    },
    { urls: ['<all_urls>'] }
  );
}

if (chrome.downloads) {
  chrome.downloads.onCreated.addListener((item) => {
    void record('download_created', {
      tabId: item.tabId ?? null,
      downloadId: item.id,
      mime: item.mime || null,
      danger: item.danger || null,
      finalUrl: urlMeta(item.finalUrl || item.url || null),
      referrer: urlMeta(item.referrer || null)
    });
  });

  chrome.downloads.onChanged.addListener((delta) => {
    void record('download_changed', {
      downloadId: delta.id,
      state: delta.state?.current || null,
      paused: delta.paused?.current ?? null,
      danger: delta.danger?.current ?? null,
      error: delta.error?.current ?? null,
      endTime: delta.endTime?.current ?? null
    });
  });
}

if (chrome.management) {
  chrome.management.onInstalled?.addListener((info) => {
    void record('extension_installed', {
      extension: normalizeExtensionInfo(info)
    });
    void recordExtensionInventorySnapshot('management_onInstalled');
  });

  chrome.management.onUninstalled?.addListener((id) => {
    void record('extension_uninstalled', {
      id
    });
    void recordExtensionInventorySnapshot('management_onUninstalled');
  });

  chrome.management.onEnabled?.addListener((info) => {
    void record('extension_enabled', {
      extension: normalizeExtensionInfo(info)
    });
    void recordExtensionInventorySnapshot('management_onEnabled');
  });

  chrome.management.onDisabled?.addListener((info) => {
    void record('extension_disabled', {
      extension: normalizeExtensionInfo(info)
    });
    void recordExtensionInventorySnapshot('management_onDisabled');
  });
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || message.type !== 'PAGE_EVENT') return;

  const tabId = sender.tab?.id ?? null;
  const payload = message.payload || {};
  const eventType = payload.eventType || 'unknown_page_event';

  if (tabId != null && tabId >= 0) {
    const patch = {
      lastPageEventType: eventType,
      lastPageEventAtMs: nowMs(),
      lastKnownUrl: urlMeta(payload.pageUrl || sender.tab?.url || null),
      lastKnownTitle: payload.title || null
    };

    if (payload.payload?.visibilityState != null) {
      patch.lastVisibilityState = payload.payload.visibilityState;
    }

    if (payload.payload?.hasFocus != null) {
      patch.lastPageFocus = payload.payload.hasFocus;
    }

    if (
      eventType === 'user_interaction_click' ||
      eventType === 'user_interaction_submit' ||
      eventType === 'window_focus'
    ) {
      patch.lastUserInteractionAtMs = nowMs();
    }

    if (
      eventType === 'history_push_state' ||
      eventType === 'history_replace_state' ||
      eventType === 'history_popstate'
    ) {
      patch.lastHistoryMutationAtMs = nowMs();
    }

    if (
      eventType === 'iframe_added' ||
      eventType === 'iframe_removed' ||
      eventType === 'iframe_attribute_changed'
    ) {
      patch.lastIframeActivityAtMs = nowMs();
    }

    if (
      eventType === 'login_form_detected' ||
      eventType === 'login_form_submitted'
    ) {
      patch.lastLoginSignalAtMs = nowMs();
    }

    updateTabState(tabId, patch);
  }

  void record('page_event', {
    tabId,
    windowId: sender.tab?.windowId ?? null,
    frameId: sender.frameId ?? null,
    pageUrl: urlMeta(sender.tab?.url || payload.pageUrl || null),
    payload
  });

  sendResponse({ ok: true });
});

setInterval(() => {
  void flush().catch((err) => console.error('flush() failed', err));
}, Recorder.flushIntervalMs);

(async () => {
  await initializeSensorIdentity();

  await record('recorder_started', {
    runtimeId: chrome.runtime.id || null,
    language: navigator.language,
    userAgent: navigator.userAgent,
    platform: navigator.platform || null
  });

  if (chrome.management) {
    await recordExtensionInventorySnapshot('startup_initial');
    setInterval(() => {
      void recordExtensionInventorySnapshot('periodic');
    }, Recorder.extensionInventoryIntervalMs);
  }
})();