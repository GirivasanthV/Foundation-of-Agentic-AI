const $ = (id) => document.getElementById(id);

function showResult(result) {
  $("status").classList.add("hidden");
  $("result").classList.remove("hidden");
  $("score").textContent = Math.round(result.risk_score || 0);
  $("verdict").textContent = result.verdict || "UNKNOWN";
  $("target").textContent = result.normalized_indicator || result.indicator || "Unknown target";
  $("summary").textContent = `${Math.round((result.confidence || 0) * 100)}% confidence · ${result.recommended_action || "MONITOR"}`;
}

async function load() {
  const { enabled = true, lastResult, lastError } = await chrome.storage.local.get(["enabled", "lastResult", "lastError"]);
  $("enabled").checked = enabled;
  if (lastResult) showResult(lastResult);
  if (lastError) $("error").textContent = lastError;
}

$("enabled").addEventListener("change", async (event) => {
  await chrome.storage.local.set({ enabled: event.target.checked });
});

$("scan").addEventListener("click", async () => {
  $("scan").disabled = true;
  $("scan").textContent = "Scanning…";
  $("error").textContent = "";
  const response = await chrome.runtime.sendMessage({ type: "SCAN_CURRENT_TAB" });
  setTimeout(async () => {
    const { lastResult, lastError } = await chrome.storage.local.get(["lastResult", "lastError"]);
    if (lastResult) showResult(lastResult);
    if (!response?.ok || lastError) $("error").textContent = response?.error || lastError;
    $("scan").disabled = false;
    $("scan").textContent = "Scan current page now";
  }, 700);
});

$("file").addEventListener("change", async (event) => {
  const [file] = event.target.files;
  if (!file) return;
  $("fileResult").classList.remove("hidden");
  $("fileResult").textContent = "Calculating SHA-256 locally…";
  try {
    const digest = await crypto.subtle.digest("SHA-256", await file.arrayBuffer());
    const hash = [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
    const response = await chrome.runtime.sendMessage({
      type: "ANALYZE_HASH",
      payload: { sha256: hash, filename: file.name, size_bytes: file.size },
    });
    if (!response?.ok) throw new Error(response?.error || "Hash lookup failed");
    const result = response.result;
    $("fileResult").textContent = `${hash}\n${result.verdict} · ${Math.round(result.risk_score)}/100 · ${result.recommended_action}`;
  } catch (error) {
    $("fileResult").textContent = error instanceof Error ? error.message : String(error);
  }
});

$("dashboard").addEventListener("click", async () => {
  const { backendUrl = "http://localhost:8000" } = await chrome.storage.local.get("backendUrl");
  const dashboard = backendUrl.replace(/:8000\/?$/, ":3000");
  await chrome.tabs.create({ url: dashboard });
});
$("options").addEventListener("click", () => chrome.runtime.openOptionsPage());
void load();

