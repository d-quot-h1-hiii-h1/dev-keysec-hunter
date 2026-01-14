// background.js — full working version (keywords + secrets + live refresh)
// UPDATED: fixes inflated secret notification counts

const scannedMap = new Map();

// --- Load regex list for secret patterns ---
async function loadRegexList() {
  try {
    const url = chrome.runtime.getURL("regax.txt");
    const r = await fetch(url);
    const txt = await r.text();
    try {
      const parsed = JSON.parse(txt);
      if (Array.isArray(parsed)) return parsed.map(e => [e.name, e.pattern]);
      else return Object.entries(parsed);
    } catch (e) {
      console.error("Failed to parse regax.txt as JSON", e);
      return [];
    }
  } catch (err) {
    console.error("Failed to fetch regax.txt", err);
    return [];
  }
}

// --- Load tech signatures ---
async function loadTechSignatures() {
  try {
    const url = chrome.runtime.getURL("tech_signatures.json");
    const r = await fetch(url);
    return await r.json();
  } catch (err) {
    console.error("Failed to fetch tech_signatures.json", err);
    return [];
  }
}

// --- Deduplicate found results (merge helper) ---
function dedupeAndMerge(prev = [], found = []) {
  const out = prev.slice();
  for (const f of found) {
    const exists = out.some(p =>
      p.name === f.name &&
      p.match === f.match &&
      p.pageUrl === f.pageUrl &&
      p.fileUrl === f.fileUrl
    );
    if (!exists) out.push(f);
  }
  return out;
}

// --- Track which domains/tabs have been scanned ---
function markScanned(domain, tabId) {
  const set = scannedMap.get(domain) || new Set();
  set.add(tabId);
  scannedMap.set(domain, set);
}
function isScanned(domain, tabId) {
  const set = scannedMap.get(domain);
  return set ? set.has(tabId) : false;
}
chrome.tabs.onRemoved.addListener(tabId => {
  for (const [domain, set] of scannedMap.entries()) {
    if (set.has(tabId)) {
      set.delete(tabId);
      if (set.size === 0) scannedMap.delete(domain);
    }
  }
});

// --- Main scanning trigger ---
chrome.webNavigation.onCompleted.addListener(async details => {
  try {
    if (details.frameId !== 0 || !details.url.startsWith("http")) return;

    const domain = new URL(details.url).hostname;
    const tabId = details.tabId;

    const data = await new Promise(res => chrome.storage.local.get(
      ["keywords", "notifyMode", "foundResults", "maxLinks", "activeSites"],
      res
    ));

    const keywords = data.keywords || [];
    const notifyMode = data.notifyMode || "notification";
    const maxLinks = data.maxLinks || "10";
    const activeSites = data.activeSites || {};
    let foundResults = data.foundResults || [];

    if (!activeSites[domain]) {
      // if toggle is OFF → clear site data and skip
      await new Promise(r => chrome.storage.local.remove(`secretsFound_${domain}`, r));
      return;
    }

    // --- TECHNOLOGY DETECTION ---
    try {
      const techSignatures = await loadTechSignatures();
      if (techSignatures.length > 0) {
        const [{ result: techScanResult }] = await chrome.scripting.executeScript({
          target: { tabId },
          func: async (signatures) => {
            const results = [];
            const headers = await fetch(location.href).then(res => res.headers);
            const cookies = document.cookie;

            for (const sig of signatures) {
              if (sig.type === "header") {
                const headerValue = headers.get(sig.header);
                if (headerValue && new RegExp(sig.pattern, "i").test(headerValue)) {
                  results.push({
                    name: sig.name,
                    engine: sig.engine,
                    payload: sig.payload,
                  });
                }
              } else if (sig.type === "cookie") {
                if (new RegExp(sig.cookie + "=", "i").test(cookies)) {
                   results.push({
                    name: sig.name,
                    engine: sig.engine,
                    payload: sig.payload,
                  });
                }
              }
            }
            return results;
          },
          args: [techSignatures]
        });

        if (Array.isArray(techScanResult) && techScanResult.length > 0) {
          const domainKey = `techFound_${domain}`;
          await chrome.storage.local.set({ [domainKey]: techScanResult });
        }
      }
    } catch (err) {
      console.error("Technology detection error:", err);
    }








   // --- KEYWORD SCANNING ---
try {
  if (keywords.length > 0) {  // ✅ Always scan, even if notifications are disabled
    const [{ result: scanResult }] = await chrome.scripting.executeScript({
      target: { tabId },
      func: async (keywordsArg, maxLinksArg) => {
        const origin = location.origin;
        const visited = new Set();
        const toVisit = [location.href];
        const results = [];
        const SAFETY_CAP = 1000;
        const limit = maxLinksArg === "all" ? SAFETY_CAP : parseInt(maxLinksArg, 10) || 10;

        async function fetchText(url) {
          try {
            const r = await fetch(url, { credentials: "include" });
            if (!r.ok) return "";
            return await r.text();
          } catch {
            return "";
          }
        }

        function extractLinksAndScripts(html, baseUrl) {
          const parser = new DOMParser();
          const doc = parser.parseFromString(html, "text/html");
          const links = Array.from(doc.querySelectorAll("a[href]"))
            .map(a => {
              try { return new URL(a.href, baseUrl).href; } catch { return null; }
            })
            .filter(Boolean)
            .filter(u => u.startsWith(origin));
          const scripts = Array.from(doc.querySelectorAll("script[src]"))
            .map(s => {
              try { return new URL(s.src, baseUrl).href; } catch { return null; }
            })
            .filter(Boolean)
            .filter(u => u.startsWith(origin));
          return { links: [...new Set(links)], scripts: [...new Set(scripts)] };
        }

        function recordMatches(text, url) {
          for (const kw of keywordsArg) {
            if (text.toLowerCase().includes(kw.toLowerCase())) {
              const lines = text.split("\n");
              lines.forEach((line, i) => {
                if (line.toLowerCase().includes(kw.toLowerCase()))
                  results.push({ keyword: kw, url, line: line.trim(), lineNum: i + 1 });
              });
            }
          }
        }

        while (toVisit.length && visited.size < limit && visited.size < SAFETY_CAP) {
          const pageUrl = toVisit.shift();
          if (!pageUrl || visited.has(pageUrl)) continue;
          visited.add(pageUrl);

          const html = await fetchText(pageUrl);
          if (!html) continue;
          recordMatches(html, pageUrl);

          const { links, scripts } = extractLinksAndScripts(html, pageUrl);

          for (const js of scripts) {
            try {
              const jsText = await fetchText(js);
              if (jsText) recordMatches(jsText, js);
            } catch (e) {
              console.warn("⚠️ JS fetch failed:", js, e);
            }
          }

          for (const l of links)
            if (!visited.has(l) && !toVisit.includes(l)) toVisit.push(l);
        }

        return results;
      },
      args: [keywords, maxLinks]
    });

    const matches = Array.isArray(scanResult) ? scanResult : [];

    if (matches.length > 0) {
      foundResults = dedupeAndMerge(foundResults, matches);
      const domainKey = `keywordsFound_${domain}`;
      await chrome.storage.local.set({
        foundResults,
        [domainKey]: matches
      });

      chrome.runtime.sendMessage({ cmd: "refreshKeywords", domain });

      // ✅ Only show notifications if enabled
      if (notifyMode !== "disabled") {
        let msg = matches.slice(0, 3).map(m => `${m.keyword} @ ${m.url}`).join("\n");
        if (matches.length > 3) msg += `\n+${matches.length - 3} more...`;

        if (notifyMode === "notification") {
          chrome.notifications.create({
            type: "basic",
            iconUrl: "icon.png",
            title: "HTML_search keywords found",
            message: msg,
            priority: 2,
            requireInteraction: true
          });
        } else if (notifyMode === "alert") {
          chrome.scripting.executeScript({
            target: { tabId },
            func: msg => alert("HTML_search:\n" + msg),
            args: [msg]
          });
        }
      }
    }
  }
} catch (err) {
  console.error("Keyword scan error:", err);
}

    // --- SECRET SCANNING (fixed counting) ---
    try {
      if (isScanned(domain, tabId)) return;

      // NOTE: DO NOT remove the stored secrets here — only clear when user toggles reset.
      const regexEntries = await loadRegexList();
      if (!regexEntries.length) {
        markScanned(domain, tabId);
        return;
      }

      const [{ result: scanResult }] = await chrome.scripting.executeScript({
        target: { tabId },
        func: async (regexEntriesArg, maxLinksArg) => {
          async function fetchText(url) {
            try {
              const r = await fetch(url, { credentials: "include" });
              if (!r.ok) return "";
              return await r.text();
            } catch {
              return "";
            }
          }

          function extractLinksAndScripts(html, baseUrl) {
            const parser = new DOMParser();
            const doc = parser.parseFromString(html, "text/html");
            const links = Array.from(doc.querySelectorAll("a[href]"))
              .map(a => {
                try { return new URL(a.href, baseUrl).href; } catch { return null; }
              })
              .filter(Boolean)
              .filter(u => u.startsWith(location.origin));
            const scripts = Array.from(doc.querySelectorAll("script[src]"))
              .map(s => {
                try { return new URL(s.src, baseUrl).href; } catch { return null; }
              })
              .filter(Boolean)
              .filter(u => u.startsWith(location.origin));
            return { links: [...new Set(links)], scripts: [...new Set(scripts)] };
          }

          const SAFETY_CAP = 1000;
          const visited = new Set();
          const toVisit = [location.href];
          const results = [];
          const limit = maxLinksArg === "all" ? SAFETY_CAP : parseInt(maxLinksArg, 10) || 10;

          while (toVisit.length && visited.size < limit && visited.size < SAFETY_CAP) {
            const pageUrl = toVisit.shift();
            if (!pageUrl || visited.has(pageUrl)) continue;
            visited.add(pageUrl);

            const html = await fetchText(pageUrl);
            if (!html) continue;

            for (const [name, pattern] of regexEntriesArg) {
              let re; try { re = new RegExp(pattern, "gi"); } catch { continue; }
              let m;
              while ((m = re.exec(html)) !== null) {
                results.push({ name, match: m[0], pageUrl, fileUrl: pageUrl });
                if (m.index === re.lastIndex) re.lastIndex++;
              }
            }

            const { links, scripts } = extractLinksAndScripts(html, pageUrl);

            for (const js of scripts) {
              try {
                const jsText = await fetchText(js);
                for (const [name, pattern] of regexEntriesArg) {
                  let re; try { re = new RegExp(pattern, "gi"); } catch { continue; }
                  let m;
                  while ((m = re.exec(jsText)) !== null) {
                    results.push({ name, match: m[0], pageUrl, fileUrl: js });
                    if (m.index === re.lastIndex) re.lastIndex++;
                  }
                }
              } catch {}
            }

            for (const l of links)
              if (!visited.has(l) && !toVisit.includes(l)) toVisit.push(l);
          }

          return results;
        },
        args: [regexEntries, maxLinks]
      });

      // Normalize foundSecrets (array)
      let foundSecrets = Array.isArray(scanResult) ? scanResult : [];

      // Deduplicate the fresh scan results first (by name+match+fileUrl)
      foundSecrets = dedupeAndMerge([], foundSecrets);

      const domainKey = `secretsFound_${domain}`;
      const prevData = await new Promise(res => chrome.storage.local.get(domainKey, res));
      const oldSecrets = prevData[domainKey] || [];

      // Build list of truly new unique secrets (not present in oldSecrets)
      const uniqueNewSecrets = foundSecrets.filter(f => {
        return !oldSecrets.some(o =>
          o.name === f.name && o.match === f.match && o.fileUrl === f.fileUrl
        );
      });

      // Merge and persist (old + new unique ones)
      const merged = dedupeAndMerge(oldSecrets, foundSecrets);
      await chrome.storage.local.set({ [domainKey]: merged });

      // Use count of truly new unique secrets for notifications
      const newCount = uniqueNewSecrets.length;

      if (newCount > 0) {
        const msg = `${newCount} new unique secret(s) found on ${domain}`;
        if (notifyMode === "notification") {
          chrome.notifications.create({
            type: "basic",
            iconUrl: "icon.png",
            title: "🔑 Secrets Found",
            message: msg,
            priority: 2
          });
        } else if (notifyMode === "alert") {
          chrome.scripting.executeScript({
            target: { tabId },
            func: msg => alert(msg),
            args: [msg]
          });
        }
      }

      markScanned(domain, tabId);
    }
	catch (err) {
      console.error("Secret scan error:", err);
      markScanned(domain, tabId);
    }
  } catch (err) {
    console.error("background onCompleted error:", err);
  }
});

// --- Reset domain scan ---
function resetDomainScan(domain) {
  if (scannedMap.has(domain)) scannedMap.delete(domain);
  const domainKey = `secretsFound_${domain}`;
  const keyKw = `keywordsFound_${domain}`;
  const techKey = `techFound_${domain}`;
  chrome.storage.local.remove([domainKey, keyKw, techKey]);
  chrome.storage.local.get(["foundResults"], d => {
    const found = d.foundResults || [];
    const filtered = found.filter(f => {
      try { return new URL(f.url).hostname !== domain; } catch { return true; }
    });
    chrome.storage.local.set({ foundResults: filtered });
  });
  console.log(`🔄 Reset complete for ${domain}`);
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg?.cmd === "resetDomain" && msg.domain) {
    resetDomainScan(msg.domain);
    sendResponse({ ok: true });
    return true;
  }
});
