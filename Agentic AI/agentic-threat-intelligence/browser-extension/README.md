# SentinelAI Browser Guard

Manifest V3 extension for Google Chrome and Microsoft Edge.

## Development installation

1. Start the SentinelAI backend and dashboard.
2. Open `chrome://extensions` in Chrome or `edge://extensions` in Edge.
3. Enable **Developer mode**.
4. Select **Load unpacked**.
5. Choose this `browser-extension` directory.
6. Open the extension settings and confirm the backend URL and token.
7. In the extension details, set **Site access** to **On all sites**. This is required for automatic visible-tab screenshots.

After updating the extension files, return to the extensions page and click the extension's **Reload** button so Chrome or Edge applies changed permissions.

Automatic analysis is enabled by default. Add banking, healthcare, internal, webmail or other sensitive domains to the exclusion list before normal browsing.

The extension analyses only active public HTTP/HTTPS tabs. Screenshot capture can be disabled independently. File checking calculates SHA-256 locally and never uploads file bytes.
