# SentinelAI architecture

## Design

SentinelAI starts as a modular monolith with isolated agent modules. The FastAPI process owns the API, orchestration and persistence. Container jobs can later separate screenshot, intelligence and model workloads without changing the API contract.

## Investigation flow

1. Validate and normalize the public URL, IP address, or SHA-256 hash.
2. Route the indicator to applicable live reputation providers.
3. Automatically capture the public page when a screenshot was not supplied.
4. Analyse captured pixels with the configured Azure multimodal deployment.
5. Retrieve and rank supporting knowledge from Azure AI Search or the curated local collection.
6. Have the orchestrator calculate a deterministic score and factor-by-factor explanation.
7. Pause high-risk or uncertain cases for analyst approval.
8. Add approved malicious indicators to the persistent response blocklist.
9. Record investigation, screenshot, decision, and blocklist transitions in the audit trail.

## Browser extension

The Manifest V3 service worker listens for completed navigation of the active tab. When automatic scanning is enabled it:

1. Rejects non-HTTP(S) pages and excluded domains.
2. Applies a per-URL cooldown to prevent repeated API use.
3. Captures the currently visible tab when screenshot analysis is enabled.
4. Sends the page URL, title and screenshot to the authenticated extension endpoint.
5. Displays the returned score as the toolbar badge.
6. Notifies the user for high or critical results.

File contents are hashed inside the extension with the Web Crypto API. Only SHA-256, filename and size metadata are submitted.

## Risk policy

The current deterministic score is intentionally explainable:

- Threat intelligence: 65%
- Visual analysis: 35%
- 0–24: Low / Allow
- 25–49: Medium / Monitor
- 50–69: High / Block recommendation
- 70–100: Critical / Block recommendation

Any block recommendation or confidence below 65% requires human approval.

## Production Azure mapping

| Local component | Azure service |
|---|---|
| Docker Compose | Azure Container Apps |
| PostgreSQL container | Azure Database for PostgreSQL |
| Redis container | Azure Managed Redis or Service Bus |
| Azurite | Azure Blob Storage |
| Local knowledge seed | Azure AI Search |
| Local structural/signature checks | Azure-hosted model deployment and external reputation providers |
| Environment file | Azure Key Vault and managed identity |
