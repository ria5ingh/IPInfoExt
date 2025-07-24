//gets current tab URL and extracts domain
chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
    const url = new URL(tabs[0].url);
    const domain = url.hostname;
    
    //get IP from domain
    const ipResponse = await fetch(`https://dns.google/resolve?name=${domain}&type=A`);
    const ipData = await ipResponse.json();
    const ip = ipData.Answer ? ipData.Answer.find(a => a.type === 1).data : 'N/A';

    //location info from ipinfo.io
    const ipinfoToken = '06af747f3a13e1';
    const geoRes = await fetch(`https://ipinfo.io/${ip}/json?token=${ipinfoToken}`);
    const geo = await geoRes.json();

    //get shodan internetDB info
    const shodanRes = await fetch(`https://internetdb.shodan.io/${ip}`);
    const shodan = await shodanRes.json();
    //make a list of suspicious open ports and tags to parse through and compare to, highlight matched tags in red

    //display results
    const output = document.getElementById("output");
    output.innerText = `
        Domain: ${domain} 
        IP: ${ip}

        Location:
        Country: ${geo.country || 'N/A'}
        City: ${geo.city || 'N/A'}
        Region: ${geo.region || 'N/A'}
        Coordinates: ${geo.loc || 'N/A'}

        Open Ports: ${shodan.ports?.join(", ") || "None"}
        Tags: ${shodan.tags?.join(", ") || "None"}
        Hostnames: ${shodan.hostnames?.join(", ") || "None"}
        `;

        if (geo.loc) {
            const mapLink = document.getElementById("mapLink");
            mapLink.href = `https://www.google.com/maps?q=${geo.loc}`;
            mapLink.style.display = "block";
            }
});