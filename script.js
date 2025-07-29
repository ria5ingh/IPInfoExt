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
                20: 5,
                21: 5,
                22: 10,
                23: 10,
                25: 5,
                53: 5,
                69: 5,
                110: 5,
                111: 5,
                135: 5,
                137: 5,
                138: 5,
                139: 5,
                143: 5,
                161: 5,
                389: 5,
                445: 10,
                512: 10,
                514: 10,
                873: 5,
                1433: 10,
                1521: 10,
                2049: 10,
                3306: 5,
                3389: 15,
                5000: 15,
                5432: 10,
                5900: 15,
                5902: 15,
                6379: 10,
                27018: 10,
                27017: 10
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

        // Process Ports using traditional loop
        const ports = shodan.ports || [];
        let portsHTML = "";
        for (let i = 0; i < ports.length; i++) {
            const port = ports[i];
            const risk = harmfulPorts[port] || 0;
            const totalScore = 1 + risk;

            riskScore += risk;
            maxScore += totalScore;

            if (risk > 0) {
                portsHTML += `<span style="color:red;">${port}</span>`;
            } else {
                portsHTML += `${port}`;
            }

            if (i < ports.length - 1) {
                portsHTML += ", ";
            }
        }

        // Process Tags using traditional loop
        const tags = shodan.tags || [];
        let tagsHTML = "";
        for (let i = 0; i < tags.length; i++) {
            const tag = tags[i];
            const key = tag.toLowerCase();
            const risk = harmfulTags[key] || 0;
            const totalScore = 1 + risk;


            riskScore += risk;
            maxScore += totalScore;


            if (risk > 0) {
                tagsHTML += `<span style="color:red;">${tag}</span>`;
            } else {
                tagsHTML += `${tag}`;
            }

            if (i < tags.length - 1) {
                tagsHTML += ", ";
            }
        }

        // Risk Percentage and Level
        let riskPercent = 0;
        let riskLevel = "Low";
        let riskColor = "green";

        riskPercent = Math.round((riskScore / maxScore) * 100);

        if (riskPercent >= 75) {
            riskLevel = "Critical";
            riskColor = "red";
        } else if (riskPercent >= 50) {
            riskLevel = "High";
            riskColor = "orange";
        } else if (riskPercent >= 25) {
            riskLevel = "Medium";
            riskColor = "goldenrod";
        }
        

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
