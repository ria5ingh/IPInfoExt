chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
    const output = document.getElementById("output");

    try {
        const url = new URL(tabs[0].url);
        const domain = url.hostname;

        // Get IP from domain
        const ipResponse = await fetch(`https://dns.google/resolve?name=${domain}&type=A`);
        const ipData = await ipResponse.json();
        const ip = ipData.Answer ? ipData.Answer.find(a => a.type === 1).data : 'N/A';

        // Get geo data
        const ipinfoToken = '06af747f3a13e1';
        const geoRes = await fetch(`https://ipinfo.io/${ip}/json?token=${ipinfoToken}`);
        const geo = await geoRes.json();

        // Get Shodan data
        const shodanRes = await fetch(`https://internetdb.shodan.io/${ip}`);
        const shodan = await shodanRes.json();

        // === Updated Risk Scores ===
        const harmfulPorts = {
            21: 7, 22: 6, 23: 10, 25: 4, 69: 8,
            110: 4, 135: 6, 139: 6, 143: 3, 445: 10,
            1433: 9, 3306: 6, 3389: 15, 5900: 12
        };

        const harmfulTags = {
            malware: 25, botnet: 25, exploit: 20, tor: 15,
            proxy: 10, vpn: 8, blacklist: 20, anonymous: 8
        };

        let riskScore = 0;

        // Ports
        const ports = shodan.ports || [];
        let portsHTML = "";
        for (let i = 0; i < ports.length; i++) {
            const port = ports[i];
            const risk = harmfulPorts[port] || 0;
            if (risk > 0) {
                riskScore += risk;
                portsHTML += `<span style="color:red;">${port}</span>`;
            } else {
                portsHTML += `${port}`;
            }

            if (i < ports.length - 1) {
                portsHTML += ", ";
            }
        }

        // Tags
        const tags = shodan.tags || [];
        let tagsHTML = "";
        for (let i = 0; i < tags.length; i++) {
            const tag = tags[i].toLowerCase();
            const risk = harmfulTags[tag] || 0;
            if (risk > 0) {
                riskScore += risk;
                tagsHTML += `<span style="color:red;">${tag}</span>`;
            } else {
                tagsHTML += `${tag}`;
            }

            if (i < tags.length - 1) {
                tagsHTML += ", ";
            }
        }

        // Risk Level
        let riskLevel = "Safe";
        let riskColor = "green";

        if (riskScore >= 51) {
            riskLevel = "Critical";
            riskColor = "red";
        } else if (riskScore >= 26) {
            riskLevel = "High";
            riskColor = "orange";
        } else if (riskScore >= 11) {
            riskLevel = "Medium";
            riskColor = "goldenrod";
        } else if (riskScore >= 1) {
            riskLevel = "Low";
            riskColor = "blue";
        }

        // Output
        output.innerHTML = `
            <strong>Domain:</strong> ${domain}<br>
            <strong>IP:</strong> ${ip}<br><br>

            <strong>Location:</strong><br>
            Country: ${geo.country || 'N/A'}<br>
            City: ${geo.city || 'N/A'}<br>
            Region: ${geo.region || 'N/A'}<br>
            Coordinates: ${geo.loc || 'N/A'}<br><br>

            <strong>Open Ports:</strong> ${portsHTML || "None"}<br>
            <strong>Tags:</strong> ${tagsHTML || "None"}<br><br>

            <strong>Risk Level:</strong> <span style="color:${riskColor};">${riskLevel}</span><br>
            <strong>Risk Score:</strong> ${riskScore}
        `;

        // Map link
        if (geo.loc) {
            const mapLink = document.getElementById("mapLink");
            mapLink.href = `https://www.google.com/maps?q=${geo.loc}`;
            mapLink.style.display = "block";
        }

    } catch (err) {
        output.innerHTML = `<span style="color:red;">Error: ${err.message}</span>`;
    }
});
