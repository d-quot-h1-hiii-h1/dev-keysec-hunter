// background.js - Refactored for maintainability

const scannedMap = new Map();

// --- Load regex list for secret patterns ---
async function loadRegexList() {
  try {
    const url = chrome.runtime.getURL("regax.txt");
    const r = await fetch(url);
    const txt = await r.text();
    try {
      const parsed = JSON.parse(txt);
      return Array.isArray(parsed) ? parsed.map(e => [e.name, e.pattern]) : Object.entries(parsed);
    } catch (e) {
      console.error("Failed to parse regax.txt as JSON", e);
      return [];
    }
  } catch (err) {
    console.error("Failed to fetch regax.txt", err);
    return [];
  }
}

// --- Deduplicate found results (merge helper) ---
function dedupeAndMerge(prev = [], found = []) {
  const out = [...prev];
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

/**
 * Injected content scanner function.
 * This runs in the context of the target page.
 */
async function contentScanner(scanType, patterns, maxLinksArg) {
  const origin = location.origin;
  const visited = new Set();
  const toVisit = [location.href];
  const results = [];
  const SAFETY_CAP = 1000;
  const limit = maxLinksArg === "all" ? SAFETY_CAP : parseInt(maxLinksArg, 10) || 10;

  async function fetchText(url) {
    try {
      const r = await fetch(url, { credentials: "include" });
      return r.ok ? await r.text() : "";
    } catch {
      return "";
    }
  }

  function extractLinksAndScripts(html, baseUrl) {
    const parser = new DOMParser();
    const doc = parser.parseFromString(html, "text/html");
    const getUrl = (node, attr) => {
      try { return new URL(node[attr], baseUrl).href; } catch { return null; }
    };
    const links = [...doc.querySelectorAll("a[href]")].map(a => getUrl(a, 'href')).filter(u => u && u.startsWith(origin));
    const scripts = [...doc.querySelectorAll("script[src]")].map(s => getUrl(s, 'src')).filter(u => u && u.startsWith(origin));
    return { links: [...new Set(links)], scripts: [...new Set(scripts)] };
  }

  function recordMatches(text, pageUrl, fileUrl) {
    if (scanType === 'keyword') {
      for (const kw of patterns) {
        if (text.toLowerCase().includes(kw.toLowerCase())) {
          text.split("\n").forEach((line, i) => {
            if (line.toLowerCase().includes(kw.toLowerCase())) {
              results.push({ keyword: kw, url: fileUrl, line: line.trim(), lineNum: i + 1 });
            }
          });
        }
      }
    } else if (scanType === 'secret') {
      for (const [name, pattern] of patterns) {
        try {
          const re = new RegExp(pattern, "gi");
          let m;
          while ((m = re.exec(text)) !== null) {
            results.push({ name, match: m[0], pageUrl, fileUrl });
            if (m.index === re.lastIndex) re.lastIndex++;
          }
        } catch {}
      }
    }
  }

  while (toVisit.length && visited.size < limit && visited.size < SAFETY_CAP) {
    const pageUrl = toVisit.shift();
    if (!pageUrl || visited.has(pageUrl)) continue;
    visited.add(pageUrl);

    const html = await fetchText(pageUrl);
    if (!html) continue;
    recordMatches(html, pageUrl, pageUrl);

    const { links, scripts } = extractLinksAndScripts(html, pageUrl);

    for (const js of scripts) {
      try {
        const jsText = await fetchText(js);
        if (jsText) recordMatches(jsText, pageUrl, js);
      } catch (e) {
        console.warn("⚠️ JS fetch failed:", js, e);
      }
    }

    for (const l of links) {
      if (!visited.has(l) && !toVisit.includes(l)) toVisit.push(l);
    }
  }
  return results;
}

// --- Unified scanning execution ---
async function executeScan(tabId, scanType, patterns, maxLinks) {
  if (!patterns || patterns.length === 0) return [];

  try {
    const [{ result }] = await chrome.scripting.executeScript({
      target: { tabId },
      func: contentScanner,
      args: [scanType, patterns, maxLinks],
    });
    return Array.isArray(result) ? result : [];
  } catch (err) {
      console.error(`Error during ${scanType} scan:`, err);
      return [];
  }
}

// --- Exposed File Scanning ---
async function checkExposedFile(url, path) {
  const to_check = url + path;
  try {
    const response = await fetch(to_check, { method: 'HEAD', redirect: 'manual' });
    if (response.status !== 404) {
      return { type: path.substring(1), url: to_check };
    }
  } catch (error) {
    // Ignore error
  }
  return null;
}

async function checkGit(url) {
  return checkExposedFile(url, "/.git/");
}

async function checkSvn(url) {
  return checkExposedFile(url, "/.svn/");
}

async function checkHg(url) {
  return checkExposedFile(url, "/.hg/");
}

async function checkEnv(url) {
  return checkExposedFile(url, "/.env");
}

async function checkDSStore(url) {
  return checkExposedFile(url, "/.DS_Store");
}

async function checkSecurityTxt(url) {
  const paths = ["/.well-known/security.txt", "/security.txt"];
  for (const path of paths) {
    const result = await checkExposedFile(url, path);
    if (result) return result;
  }
  return null;
}

// --- Main scanning trigger ---
chrome.webNavigation.onCompleted.addListener(async details => {
  if (details.frameId !== 0 || !details.url.startsWith("http")) return;

  const domain = new URL(details.url).hostname;
  const tabId = details.tabId;
  const url = details.url;

  try {
    const data = await chrome.storage.local.get(["keywords", "notifyMode", "foundResults", "maxLinks", "activeSites", "exposedFileChecks", "customFiles"]);
    const { keywords = [], notifyMode = "notification", maxLinks = "10", activeSites = {}, foundResults = [], exposedFileChecks = {}, customFiles = [] } = data;

    if (!activeSites[domain]) {
      await chrome.storage.local.remove(`secretsFound_${domain}`);
      await chrome.storage.local.remove(`exposedFiles_${domain}`);
      return;
    }

    // --- KEYWORD SCANNING ---
    const keywordMatches = await executeScan(tabId, 'keyword', keywords, maxLinks);
    if (keywordMatches.length > 0) {
      const mergedKeywords = dedupeAndMerge(foundResults, keywordMatches);
      const domainKey = `keywordsFound_${domain}`;
      await chrome.storage.local.set({ foundResults: mergedKeywords, [domainKey]: keywordMatches });

      chrome.runtime.sendMessage({ cmd: "refreshKeywords", domain });

      if (notifyMode !== "disabled") {
        let msg = keywordMatches.slice(0, 3).map(m => `${m.keyword} @ ${m.url}`).join("\n");
        if (keywordMatches.length > 3) msg += `\n+${keywordMatches.length - 3} more...`;

        if (notifyMode === "notification") {
          chrome.notifications.create({
            type: "basic", iconUrl: "icon.png", title: "HTML_search keywords found",
            message: msg, priority: 2, requireInteraction: true,
          });
        } else if (notifyMode === "alert") {
          chrome.scripting.executeScript({
            target: { tabId },
            func: msg => alert("HTML_search:\n" + msg),
            args: [msg],
          });
        }
      }
    }

    // --- SECRET SCANNING ---
    if (!isScanned(domain, tabId)) {
      const regexEntries = await loadRegexList();
      const secretMatches = await executeScan(tabId, 'secret', regexEntries, maxLinks);

      if (secretMatches.length > 0) {
        const dedupedSecrets = dedupeAndMerge([], secretMatches);
        const domainKey = `secretsFound_${domain}`;
        const { [domainKey]: oldSecrets = [] } = await chrome.storage.local.get(domainKey);

        const uniqueNewSecrets = dedupedSecrets.filter(f =>
          !oldSecrets.some(o => o.name === f.name && o.match === f.match && o.fileUrl === f.fileUrl)
        );

        const mergedSecrets = dedupeAndMerge(oldSecrets, dedupedSecrets);
        await chrome.storage.local.set({ [domainKey]: mergedSecrets });

        const newCount = uniqueNewSecrets.length;
        if (newCount > 0) {
          const msg = `${newCount} new unique secret(s) found on ${domain}`;
          if (notifyMode === "notification") {
            chrome.notifications.create({
              type: "basic", iconUrl: "icon.png", title: "🔑 Secrets Found",
              message: msg, priority: 2,
            });
          } else if (notifyMode === "alert") {
            chrome.scripting.executeScript({
              target: { tabId },
              func: msg => alert(msg),
              args: [msg],
            });
          }
        }
      }
    }

    // --- EXPOSED FILE SCANNING ---
    const origin = new URL(url).origin;
    const checksToRun = [];
    if (exposedFileChecks.git) checksToRun.push(checkGit(origin));
    if (exposedFileChecks.svn) checksToRun.push(checkSvn(origin));
    if (exposedFileChecks.hg) checksToRun.push(checkHg(origin));
    if (exposedFileChecks.env) checksToRun.push(checkEnv(origin));
    if (exposedFileChecks.ds_store) checksToRun.push(checkDSStore(origin));
    if (exposedFileChecks.securitytxt) checksToRun.push(checkSecurityTxt(origin));

    customFiles.forEach(file => {
      checksToRun.push(checkExposedFile(origin, `/${file}`));
    });

    const exposedFileResults = (await Promise.all(checksToRun)).filter(Boolean);

    if (exposedFileResults.length > 0) {
      const domainKey = `exposedFiles_${domain}`;
      const { [domainKey]: oldExposedFiles = [] } = await chrome.storage.local.get(domainKey);
      const newExposedFiles = exposedFileResults.filter(f => !oldExposedFiles.some(o => o.url === f.url));

      if (newExposedFiles.length > 0) {
        const mergedExposedFiles = [...oldExposedFiles, ...newExposedFiles];
        await chrome.storage.local.set({ [domainKey]: mergedExposedFiles });

        if (notifyMode !== "disabled") {
          const msg = `${newExposedFiles.length} new exposed file(s) found on ${domain}`;
          if (notifyMode === "notification") {
            chrome.notifications.create({
              type: "basic", iconUrl: "icon.png", title: "📁 Exposed Files Found",
              message: msg, priority: 2,
            });
          } else if (notifyMode === "alert") {
            chrome.scripting.executeScript({
              target: { tabId },
              func: msg => alert(msg),
              args: [msg],
            });
          }
        }
      }
    }

    markScanned(domain, tabId);

  } catch (err) {
    console.error("background onCompleted error:", err);
  }
});

// --- Reset domain scan ---
function resetDomainScan(domain) {
  scannedMap.delete(domain);
  const secretsKey = `secretsFound_${domain}`;
  const keywordsKey = `keywordsFound_${domain}`;
  const exposedFilesKey = `exposedFiles_${domain}`;
  chrome.storage.local.remove([secretsKey, keywordsKey, exposedFilesKey]);

  chrome.storage.local.get("foundResults", d => {
    const filtered = (d.foundResults || []).filter(f => {
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
  return false;
});
