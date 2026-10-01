# SentinelAI

Agentic threat intelligence and human-approved response for suspicious public URLs and IP addresses. The MVP combines a LangGraph agent workflow, deterministic risk scoring, RAG evidence, VLM integration points and an auditable approval flow.

## What works now

- URL/IP normalization and basic SSRF protection
- Multi-agent LangGraph workflow
- Live provider routing for VirusTotal, AbuseIPDB and URLScan when keys are configured
- Azure vision-language screenshot analysis when a multimodal deployment is configured
- Automatic SSRF-guarded website screenshot capture from the dashboard
- Explainable scoring with factor weights, contributions, thresholds, confidence rationale and limitations
- Curated local cybersecurity RAG retrieval with per-reference relevance explanations
- Risk score, verdict and confidence
- Human approve/reject/monitor decisions with analyst comments
- Persistent response blocklist with removal controls
- Complete audit trail for investigations, decisions and blocklist changes
- PostgreSQL investigation and audit storage
- Fully interactive React SOC dashboard with Investigations, Approval Queue, Blocklist, Audit Trail and System Status views
- Chrome/Edge browser extension with automatic active-page analysis
- Visible-tab screenshot capture for VLM analysis
- Local SHA-256 file hashing with VirusTotal lookup integration
- Azure clients and infrastructure starter

The project always runs its real analysis workflow. Local URL-structure and known-signature checks work without paid keys; external reputation and screenshot VLM evidence activate when their credentials are configured. Missing providers are shown as unavailable and are never replaced with synthetic verdicts.

## Windows prerequisites

- Windows 11
- Docker Desktop running through Windows
- PowerShell
- Git

You do not need to open or work inside WSL.

## Start with Docker Desktop

Open PowerShell in the project directory:

```powershell
Copy-Item .env.example .env
docker compose up --build
```

Open:

- Dashboard: http://localhost:3000
- Backend documentation: http://localhost:8000/docs
- Health endpoint: http://localhost:8000/health

## Install the Chrome or Edge extension

After Docker is running:

1. Open `chrome://extensions` or `edge://extensions`.
2. Enable **Developer mode**.
3. Click **Load unpacked**.
4. Select the project's `browser-extension` directory.
5. Open the SentinelAI extension settings.
6. Keep the backend as `http://localhost:8000` and token as `local-development-token` for local development.
7. Open the extension details and set **Site access** to **On all sites**.

The extension automatically analyses the active public page after it loads. It displays the risk score on the extension badge. Use its popup to rescan the page or select a file for local SHA-256 calculation.

Screenshot analysis is enabled initially. Before normal browsing, review the privacy warning and add sensitive domains to the exclusion list. You can disable screenshot capture while keeping URL/IP checks enabled.

Try a harmless structural-analysis indicator:

```text
https://verify-account-login.example
```

Stop the project:

```powershell
docker compose down
```

To remove local database and emulator volumes as well:

```powershell
docker compose down --volumes
```

## Run without Docker

Backend:

```powershell
cd backend
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m playwright install chromium
$env:DATABASE_URL = "sqlite:///./sentinel.db"
uvicorn app.main:app --reload
```

Frontend, in another PowerShell window:

```powershell
cd frontend
npm install
npm run dev
```

## Configuration

Copy `.env.example` to `.env`. The local analyzers work immediately; add the external threat-intelligence and Azure multimodal credentials required for your deployment. Azure AI Search and Blob Storage are optional.

Never commit `.env` or API keys.

### Configure external intelligence and Azure VLM

Set the following values in `.env`:

```dotenv
VIRUSTOTAL_API_KEY=your-key
ABUSEIPDB_API_KEY=your-key
URLSCAN_API_KEY=your-key
AZURE_OPENAI_ENDPOINT=https://your-resource.openai.azure.com
AZURE_OPENAI_API_KEY=your-key
AZURE_OPENAI_VISION_DEPLOYMENT=your-vision-deployment-name
```

Restart the backend after changing `.env`:

```powershell
docker compose down
docker compose up --build
```

Live routing is deliberately provider-specific:

| Indicator | Services |
|---|---|
| Page URL | VirusTotal URL report and URLScan historical lookup |
| Resolved public IP | AbuseIPDB and VirusTotal IP report |
| SHA-256 file hash | VirusTotal file report |
| Visible screenshot | Azure vision-capable model deployment |

AbuseIPDB does not analyse files, and URLScan is not a file-hash service. The extension therefore sends each indicator only to an applicable provider. It searches existing URLScan results and does not automatically submit visited pages for new public scans.

## Azure deployment path

1. Provision Azure Blob Storage, Container Registry and logging using `infrastructure/azure/main.bicep`.
2. Provision Azure Database for PostgreSQL and Azure AI Search.
3. Build and push the backend/frontend images to Azure Container Registry.
4. Deploy the API and workers to Azure Container Apps.
5. Put secrets in Azure Key Vault and use managed identities where supported.
6. Optionally replace the curated local RAG index with Azure AI Search and configure an Azure vision-capable model deployment.
7. Keep response mode set to `simulate` until authentication, approval and rollback tests pass.

## API

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/health` | Service status |
| POST | `/api/v1/investigations` | Analyse a URL, IP or SHA-256; automatically capture URL screenshots unless disabled or an image is supplied |
| GET | `/api/v1/investigations` | List investigations |
| GET | `/api/v1/investigations/{id}` | Investigation detail |
| POST | `/api/v1/investigations/{id}/decision` | Approve, reject or monitor |
| GET | `/api/v1/audit` | Recent audit events |
| GET | `/api/v1/blocklist` | List approved blocklist entries |
| DELETE | `/api/v1/blocklist/{id}` | Remove an active blocklist entry |
| GET | `/api/v1/system/status` | Provider and feature readiness |
| POST | `/api/v1/extension/analyze-page` | Extension URL/IP/screenshot analysis |
| POST | `/api/v1/extension/analyze-hash` | Extension SHA-256 analysis |

## Production boundary

The live external-intelligence and Azure VLM adapters activate when credentials are supplied. The included curated RAG store works locally; Azure AI Search remains an optional production-scale replacement. The built-in blocklist is fully functional, while external firewall/proxy enforcement remains simulated until an organization-specific response adapter, authentication, and rollback controls are configured.
