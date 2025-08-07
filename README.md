IP Inspector - Chrome Extension:

IP Inspector is a Chrome extension that lets you analyze websites by fetching their IP address, location, open ports, and security-related tags using Shodan InternetDB and GeoNet (ipinfo.io) APIs. It helps assess the risk level of a website based on known vulnerable ports and tags associated with malware, botnets, and more.

Features:
* Extracts IP address from the current tab’s domain
* Displays geographic data (country, city, region, coordinates)
* Shows open ports and highlights risky ones
* Lists Shodan tags indicating potential threats
* Computes a risk score and labels the site as Safe, Low, Medium, High, or Critical
* Includes a direct link to view the server’s location on Google Maps

Project Structure:

IP-Inspector/

├── manifest.json         # Chrome extension config

├── index.html            # Popup UI

├── style.css             # Popup styling

├── script.js             # Core logic and API calls

APIs Used:
* Shodan InternetDB – Retrieves open ports and tags
* ipinfo.io – Fetches geographic data (via GeoNet API)
* Google DNS over HTTPS – Resolves domain to IP

Risk Assessment Logic:
The extension uses custom scoring tables to assess risk

Risky Ports (examples)
* 23 (Telnet) - Insecure and deprecated - 10 pts
* 445	(SMB) - Exploitable by ransomware - 10 pts
* 3389 (RDP) - Common target for attacks - 15 pts

Dangerous Tags:
Tags like malware, botnet, tor, and blacklist increase the site's risk score.

Risk Levels:
* Safe (0)
* Low (1–10)
* Medium (11–25)
* High (26–50)
* Critical (51+)

How It Works: 
* Popup Opens → Automatically grabs the active tab's URL
* Domain to IP → Uses Google DNS API to resolve domain
* Geolocation → Fetches IP location from ipinfo.io
* Shodan Scan → Gets open ports + tags from InternetDB
* Risk Score → Evaluated using weighted scores
* Display Info → Results rendered with severity colors

Installation:
1. Clone/download this repository
2. Go to chrome://extensions
3. Enable Developer Mode
4. Click Load unpacked
5. Select the IPInfoExt folder
6. Click the extension icon on any website to inspect it!

(Disclaimers: This tool is for educational and research purposes only. Always comply with ethical guidelines and never scan or probe systems without permission.)

Built by Lavanya Joshi, Ria Singh, & Anika Atluri
