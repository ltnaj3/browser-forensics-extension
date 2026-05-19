(() => {
  'use strict';

  if (window.__contentInspectorLoaded) return;
  window.__contentInspectorLoaded = true;

  const inspectorBootAt = performance.now();
  let lastUserInteractionAt = null;
  const recentEventTimes = new Map();
  let clsValue = 0;
  let clsEntries = [];
  let latestLcpEntry = null;
  let hasSentPerfSummary = false;

  function nowIso() {
    return new Date().toISOString();
  }

  function perfNow() {
    return Math.round(performance.now() * 1000) / 1000;
  }

  function round(n) {
    return typeof n === 'number' ? Math.round(n * 1000) / 1000 : null;
  }

  function shouldThrottle(eventType, windowMs) {
    const now = Date.now();
    const previous = recentEventTimes.get(eventType) || 0;
    recentEventTimes.set(eventType, now);
    return now - previous < windowMs;
  }

  function send(eventType, payload = {}) {
    try {
      chrome.runtime.sendMessage({
        type: 'PAGE_EVENT',
        payload: {
          schemaVersion: '1.0.0',
          eventType,
          timestamp: nowIso(),
          pageUrl: location.href,
          pageOrigin: location.origin,
          title: document.title,
          payload
        }
      });
    } catch (_) {}
  }

  function measureOperation(name, fn) {
    const startedAt = perfNow();
    const result = fn();
    const endedAt = perfNow();

    send('extension_perf_measurement', {
      name,
      startedAt,
      endedAt,
      durationMs: round(endedAt - startedAt)
    });

    return result;
  }

  function safeUrl(raw) {
    if (!raw) return null;
    try {
      const u = new URL(raw, location.href);
      return {
        raw: u.href,
        origin: u.origin,
        scheme: u.protocol.replace(':', ''),
        host: u.hostname || null,
        path: u.pathname || '/',
        queryPresent: !!u.search,
        fragmentPresent: !!u.hash
      };
    } catch {
      return {
        raw,
        origin: null,
        scheme: null,
        host: null,
        path: null,
        queryPresent: null,
        fragmentPresent: null
      };
    }
  }

  function visibleState(el) {
    const style = getComputedStyle(el);
    const rect = el.getBoundingClientRect();

    return {
      width: rect.width,
      height: rect.height,
      display: style.display,
      visibility: style.visibility,
      opacity: style.opacity,
      hidden:
        style.display === 'none' ||
        style.visibility === 'hidden' ||
        Number(style.opacity) === 0 ||
        rect.width === 0 ||
        rect.height === 0
    };
  }

  function iframeMeta(iframe, index) {
    const src = iframe.getAttribute('src');
    const sandbox = iframe.getAttribute('sandbox');
    const loading = iframe.getAttribute('loading');
    const referrerPolicy = iframe.getAttribute('referrerpolicy');
    const name = iframe.getAttribute('name');
    const title = iframe.getAttribute('title');
    const id = iframe.id || null;
    const srcdocPresent = iframe.hasAttribute('srcdoc');

    let sameOrigin = null;
    let contentAccessible = false;

    try {
      void iframe.contentWindow?.location?.href;
      contentAccessible = true;
      if (src) {
        const parsed = new URL(src, location.href);
        sameOrigin = parsed.origin === location.origin;
      }
    } catch {
      contentAccessible = false;
      if (src) {
        try {
          const parsed = new URL(src, location.href);
          sameOrigin = parsed.origin === location.origin;
        } catch {
          sameOrigin = null;
        }
      }
    }

    return {
      index,
      id,
      name,
      title,
      src: safeUrl(src),
      srcdocPresent,
      sandbox,
      loading,
      referrerPolicy,
      sameOrigin,
      contentAccessible,
      visibility: visibleState(iframe)
    };
  }

  function classifyForm(form) {
    const passwordInputs = form.querySelectorAll('input[type="password"]').length;
    const emailInputs = form.querySelectorAll('input[type="email"]').length;
    const textInputs = form.querySelectorAll('input[type="text"], input:not([type])').length;

    return {
      id: form.id || null,
      name: form.getAttribute('name') || null,
      action: safeUrl(form.getAttribute('action')),
      method: (form.getAttribute('method') || 'get').toUpperCase(),
      passwordFieldCount: passwordInputs,
      emailFieldCount: emailInputs,
      textFieldCount: textInputs,
      containsPasswordField: passwordInputs > 0
    };
  }

  function loginFormsSnapshot() {
    return Array.from(document.forms || [])
      .filter((form) => form.querySelector('input[type="password"]'))
      .map(classifyForm);
  }

  function iframeSnapshot() {
    return Array.from(document.querySelectorAll('iframe')).map((iframe, index) =>
      iframeMeta(iframe, index)
    );
  }

  function pageSnapshot(reason) {
    return measureOperation('pageSnapshot', () => ({
      schemaVersion: '1.0.0',
      reason,
      timestamp: nowIso(),
      url: location.href,
      origin: location.origin,
      title: document.title,
      visibilityState: document.visibilityState,
      hasFocus: document.hasFocus(),
      lastUserInteractionAt,
      iframeCount: document.querySelectorAll('iframe').length,
      loginFormCount: loginFormsSnapshot().length,
      iframes: iframeSnapshot(),
      loginForms: loginFormsSnapshot()
    }));
  }

  function getNavEntry() {
    const nav = performance.getEntriesByType('navigation')[0];
    if (!nav) return null;

    return {
      entryType: nav.entryType || 'navigation',
      type: nav.type || null,
      startTime: round(nav.startTime),
      duration: round(nav.duration),
      domInteractive: round(nav.domInteractive),
      domContentLoadedEventStart: round(nav.domContentLoadedEventStart),
      domContentLoadedEventEnd: round(nav.domContentLoadedEventEnd),
      loadEventStart: round(nav.loadEventStart),
      loadEventEnd: round(nav.loadEventEnd),
      responseStart: round(nav.responseStart),
      responseEnd: round(nav.responseEnd),
      fetchStart: round(nav.fetchStart),
      domainLookupStart: round(nav.domainLookupStart),
      domainLookupEnd: round(nav.domainLookupEnd),
      connectStart: round(nav.connectStart),
      connectEnd: round(nav.connectEnd),
      requestStart: round(nav.requestStart),
      activationStart: round(nav.activationStart),
      transferSize: nav.transferSize ?? null,
      encodedBodySize: nav.encodedBodySize ?? null,
      decodedBodySize: nav.decodedBodySize ?? null
    };
  }

  function emitNavTimingSummary(reason = 'load') {
    const nav = getNavEntry();
    if (!nav) return;

    send('page_nav_timing', {
      reason,
      navigation: nav
    });
  }

  function serializeLcpEntry(entry) {
    if (!entry) return null;

    return {
      startTime: round(entry.startTime),
      renderTime: round(entry.renderTime || 0),
      loadTime: round(entry.loadTime || 0),
      size: entry.size ?? null,
      id: entry.id || null,
      url: entry.url || null,
      elementTag: entry.element?.tagName || null
    };
  }

  function emitLcp(reason = 'candidate') {
    if (!latestLcpEntry) return;

    send('page_lcp', {
      reason,
      lcp: serializeLcpEntry(latestLcpEntry)
    });
  }

  function emitCls(reason = 'final') {
    send('page_cls', {
      reason,
      clsValue: round(clsValue),
      sources: clsEntries.slice(-10)
    });
  }

  function emitPerfSummary(reason = 'final') {
    if (hasSentPerfSummary && reason !== 'visibility_hidden') return;
    hasSentPerfSummary = true;

    send('page_perf_summary', {
      reason,
      navigation: getNavEntry(),
      lcp: serializeLcpEntry(latestLcpEntry),
      clsValue: round(clsValue),
      extensionBootDurationMs: round(perfNow() - inspectorBootAt),
      visibilityState: document.visibilityState,
      hasFocus: document.hasFocus()
    });
  }

  function observeWebVitals() {
    try {
      const lcpObserver = new PerformanceObserver((list) => {
        const entries = list.getEntries();
        const lastEntry = entries[entries.length - 1];
        if (!lastEntry) return;
        latestLcpEntry = lastEntry;
        send('page_lcp_candidate', {
          lcp: serializeLcpEntry(lastEntry)
        });
      });

      lcpObserver.observe({ type: 'largest-contentful-paint', buffered: true });

      const paintObserver = new PerformanceObserver((list) => {
        for (const entry of list.getEntries()) {
          if (entry.name === 'first-contentful-paint') {
            send('page_fcp', {
              startTime: round(entry.startTime)
            });
          }
        }
      });

      paintObserver.observe({ type: 'paint', buffered: true });

      const clsObserver = new PerformanceObserver((list) => {
        for (const entry of list.getEntries()) {
          if (entry.hadRecentInput) continue;
          clsValue += entry.value;
          clsEntries.push({
            value: round(entry.value),
            startTime: round(entry.startTime),
            sources: (entry.sources || []).slice(0, 5).map((source) => ({
              nodeTag: source.node?.tagName || null,
              previousRect: source.previousRect || null,
              currentRect: source.currentRect || null
            }))
          });
        }
      });

      clsObserver.observe({ type: 'layout-shift', buffered: true });

      document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'hidden') {
          emitLcp('final');
          emitCls('final');
          emitPerfSummary('visibility_hidden');
        }
      });

      window.addEventListener('pagehide', () => {
        emitLcp('pagehide');
        emitCls('pagehide');
        emitPerfSummary('pagehide');
      });
    } catch (err) {
      send('extension_perf_observer_error', {
        error: err?.message || String(err)
      });
    }
  }

  function reportInitialSignals() {
    send('page_loaded', {
      visibilityState: document.visibilityState,
      hasFocus: document.hasFocus(),
      iframeCount: document.querySelectorAll('iframe').length,
      loginFormCount: loginFormsSnapshot().length,
      extensionBootDurationMs: round(perfNow() - inspectorBootAt)
    });

    const loginForms = loginFormsSnapshot();
    if (loginForms.length) {
      send('login_form_detected', {
        count: loginForms.length,
        forms: loginForms
      });
    }
  }

  function hookHistory() {
    const originalPushState = history.pushState;
    const originalReplaceState = history.replaceState;

    history.pushState = function (...args) {
      const result = originalPushState.apply(this, args);
      send('history_push_state', {
        url: location.href
      });
      return result;
    };

    history.replaceState = function (...args) {
      const result = originalReplaceState.apply(this, args);
      send('history_replace_state', {
        url: location.href
      });
      return result;
    };

    window.addEventListener('popstate', () => {
      send('history_popstate', {
        url: location.href
      });
    });
  }

  function watchVisibility() {
    document.addEventListener('visibilitychange', () => {
      if (shouldThrottle('visibility_change', 500)) return;
      send('visibility_change', {
        visibilityState: document.visibilityState,
        hasFocus: document.hasFocus()
      });
    });

    window.addEventListener('focus', () => {
      lastUserInteractionAt = nowIso();
      send('window_focus', {
        hasFocus: document.hasFocus()
      });
    });

    window.addEventListener('blur', () => {
      send('window_blur', {
        hasFocus: document.hasFocus()
      });
    });

    window.addEventListener('pagehide', () => {
      send('page_hide', {
        visibilityState: document.visibilityState,
        hasFocus: document.hasFocus()
      });
    });

    window.addEventListener('beforeunload', () => {
      send('before_unload', {
        visibilityState: document.visibilityState,
        hasFocus: document.hasFocus()
      });
    });
  }

  function watchLoginForms() {
    document.addEventListener(
      'submit',
      (event) => {
        const form = event.target;
        if (!(form instanceof HTMLFormElement)) return;
        if (!form.querySelector('input[type="password"]')) return;

        lastUserInteractionAt = nowIso();

        send('user_interaction_submit', {
          hasFocus: document.hasFocus()
        });

        send('login_form_submitted', {
          form: classifyForm(form)
        });
      },
      true
    );
  }

  function watchUserInteractions() {
    document.addEventListener(
      'click',
      () => {
        if (shouldThrottle('user_interaction_click', 1000)) return;
        lastUserInteractionAt = nowIso();
        send('user_interaction_click', {
          hasFocus: document.hasFocus(),
          visibilityState: document.visibilityState
        });
      },
      true
    );
  }

  function watchIframes() {
    const observed = new WeakMap();

    function emitIframeAdded(iframe) {
      send('iframe_added', {
        frame: iframeMeta(iframe, -1)
      });
    }

    function emitIframeRemoved() {
      send('iframe_removed', {
        note: 'iframe removed from DOM'
      });
    }

    function observeIframeAttributes(iframe) {
      if (observed.has(iframe)) return;

      const observer = new MutationObserver((mutations) => {
        for (const mutation of mutations) {
          if (mutation.type === 'attributes') {
            send('iframe_attribute_changed', {
              attribute: mutation.attributeName,
              frame: iframeMeta(iframe, -1)
            });
          }
        }
      });

      observer.observe(iframe, {
        attributes: true,
        attributeFilter: ['src', 'sandbox', 'style', 'class', 'hidden', 'loading', 'referrerpolicy']
      });

      observed.set(iframe, observer);
    }

    measureOperation('initialIframeObserverSetup', () => {
      document.querySelectorAll('iframe').forEach((iframe) => {
        observeIframeAttributes(iframe);
      });
    });

    const rootObserver = new MutationObserver((mutations) => {
      let detectedLoginForms = false;

      for (const mutation of mutations) {
        for (const node of mutation.addedNodes) {
          if (node instanceof HTMLIFrameElement) {
            observeIframeAttributes(node);
            emitIframeAdded(node);
          } else if (node instanceof Element) {
            node.querySelectorAll?.('iframe').forEach((iframe) => {
              observeIframeAttributes(iframe);
              emitIframeAdded(iframe);
            });

            if (node.matches?.('form') || node.querySelector?.('form')) {
              detectedLoginForms = true;
            }
          }
        }

        for (const node of mutation.removedNodes) {
          if (node instanceof HTMLIFrameElement) {
            emitIframeRemoved();
          } else if (node instanceof Element && node.querySelector?.('iframe')) {
            node.querySelectorAll('iframe').forEach(() => emitIframeRemoved());
          }
        }
      }

      if (detectedLoginForms) {
        const loginForms = loginFormsSnapshot();
        if (loginForms.length) {
          send('login_form_detected', {
            count: loginForms.length,
            forms: loginForms
          });
        }
      }
    });

    rootObserver.observe(document.documentElement, {
      childList: true,
      subtree: true
    });
  }

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (!message) return;

    if (message.type === 'GET_PAGE_SNAPSHOT') {
      sendResponse(pageSnapshot(message.reason || 'manual'));
    }
  });

  observeWebVitals();
  hookHistory();
  watchVisibility();
  watchUserInteractions();
  watchLoginForms();
  watchIframes();

  window.addEventListener('load', () => {
    emitNavTimingSummary('window_load');
    emitPerfSummary('window_load');
  });

  if (document.readyState === 'loading') {
    document.addEventListener(
      'DOMContentLoaded',
      () => {
        reportInitialSignals();
        emitNavTimingSummary('dom_content_loaded');
      },
      { once: true }
    );
  } else {
    reportInitialSignals();
    emitNavTimingSummary('already_loaded');
  }
})();