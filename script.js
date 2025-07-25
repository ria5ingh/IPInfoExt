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

        // === Risk Scoring ===
        const harmfulPorts = {
            21: 5,
            22: 8,
            23: 10,
            25: 5,
            69: 6,
            110: 4,
            135: 6,
            139: 6,
            143: 4,
            445: 8,
            1433: 10,
            3306: 7,
            3389: 15,
            5900: 12
        };

        const harmfulTags = {
            malware: 20,
            vpn: 5,
            proxy: 5,
            tor: 15,
            botnet: 25,
            exploit: 20,
            anonymous: 10,
            blacklist: 20
        };

        let riskScore = 0;
        let maxScore = 0;

        // Ports HTML & score
        const portsHTML = (shodan.ports || []).map(port => {
            if (harmfulPorts[port]) {
                riskScore += harmfulPorts[port];
                maxScore += harmfulPorts[port];
                return `<span style="color:red;">${port}</span>`;
            } else {
                return `${port}`;
            }
        }).join(", ");

        // Tags HTML & score
        const tagsHTML = (shodan.tags || []).map(tag => {
            const key = tag.toLowerCase();
            if (harmfulTags[key]) {
                riskScore += harmfulTags[key];
                maxScore += harmfulTags[key];
                return `<span style="color:red;">${tag}</span>`;
            } else {
                return `${tag}`;
            }
        }).join(", ");

        // Risk Percentage & Level
        const riskPercent = maxScore > 0 ? Math.min(100, Math.round((riskScore / maxScore) * 100)) : 0;
        let riskLevel = "Low";
        if (riskPercent >= 75) riskLevel = "Critical";
        else if (riskPercent >= 50) riskLevel = "High";
        else if (riskPercent >= 25) riskLevel = "Medium";

        // === Output ===
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

            <strong>Risk Level:</strong> <span style="color:${riskPercent >= 75 ? 'red' : riskPercent >= 50 ? 'orange' : riskPercent >= 25 ? 'goldenrod' : 'green'};">${riskLevel}</span><br>
            <strong>Risk Score:</strong> ${riskScore}/${maxScore} (${riskPercent}%)
        `;

        // Map
        if (geo.loc) {
            const mapLink = document.getElementById("mapLink");
            mapLink.href = `https://www.google.com/maps?q=${geo.loc}`;
            mapLink.style.display = "block";
        }

    } catch (err) {
        output.innerHTML = `<span style="color:red;">Error: ${err.message}</span>`;
    }
});
