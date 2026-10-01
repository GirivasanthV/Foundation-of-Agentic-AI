const DEFAULTS = {
  enabled: true,
  captureScreenshots: true,
  backendUrl: "http://localhost:8000",
  extensionToken: "local-development-token",
  excludedDomains: ["localhost", "127.0.0.1"],
  cooldownMinutes: 5,
};
const $ = (id) => document.getElementById(id);

async function load() {
  const settings = await chrome.storage.local.get(DEFAULTS);
  $("enabled").checked = settings.enabled;
  $("captureScreenshots").checked = settings.captureScreenshots;
  $("backendUrl").value = settings.backendUrl;
  $("extensionToken").value = settings.extensionToken;
  $("cooldownMinutes").value = settings.cooldownMinutes;
  $("excludedDomains").value = settings.excludedDomains.join("\n");
}

$("form").addEventListener("submit", async (event) => {
  event.preventDefault();
  await chrome.storage.local.set({
    enabled: $("enabled").checked,
    captureScreenshots: $("captureScreenshots").checked,
    backendUrl: $("backendUrl").value.replace(/\/$/, ""),
    extensionToken: $("extensionToken").value,
    cooldownMinutes: Number($("cooldownMinutes").value) || 5,
    excludedDomains: $("excludedDomains").value.split(/\r?\n/).map((value) => value.trim().toLowerCase()).filter(Boolean),
  });
  $("saved").textContent = "Saved";
  setTimeout(() => { $("saved").textContent = ""; }, 1800);
});
void load();

