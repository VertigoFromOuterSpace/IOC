document.addEventListener('DOMContentLoaded', () => {
    const iocInput = document.getElementById('ioc-input');
    const analyzeBtn = document.getElementById('analyze-btn');
    const resultsContainer = document.getElementById('results-container');

    analyzeBtn.addEventListener('click', () => {
        const iocs = iocInput.value.split('\n').filter(line => line.trim() !== '');
        resultsContainer.innerHTML = ''; // Limpa resultados anteriores

        if (iocs.length === 0) {
            resultsContainer.innerHTML = '<p style="color: #aaa; text-align: center;">Nenhum indicador fornecido.</p>';
            return;
        }

        iocs.forEach(ioc => {
            const trimmedIoc = ioc.trim();
            const iocType = getIocType(trimmedIoc);
            const resultElement = createResultElement(trimmedIoc, iocType);
            resultsContainer.appendChild(resultElement);
        });
    });

    function getIocType(ioc) {
        // Regex para identificar tipos de IOC
        const ipv4Regex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
        const domainRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
        const md5Regex = /^[a-f0-9]{32}$/i;
        const sha1Regex = /^[a-f0-9]{40}$/i;
        const sha256Regex = /^[a-f0-9]{64}$/i;

        if (ipv4Regex.test(ioc)) return 'IPv4';
        if (domainRegex.test(ioc)) return 'Domínio';
        if (md5Regex.test(ioc)) return 'Hash MD5';
        if (sha1Regex.test(ioc)) return 'Hash SHA1';
        if (sha256Regex.test(ioc)) return 'Hash SHA256';
        
        return 'Desconhecido';
    }

    function createResultElement(ioc, type) {
        const itemDiv = document.createElement('div');
        itemDiv.className = 'result-item';

        let linksHtml = '';
        switch (type) {
            case 'IPv4':
                linksHtml = `
                    <a href="https://www.virustotal.com/gui/ip-address/${ioc}" target="_blank">VirusTotal</a>
                    <a href="https://www.abuseipdb.com/check/${ioc}" target="_blank">AbuseIPDB</a>
                    <a href="https://www.shodan.io/host/${ioc}" target="_blank">Shodan</a>
                `;
                break;
            case 'Domínio':
                linksHtml = `
                    <a href="https://www.virustotal.com/gui/domain/${ioc}" target="_blank">VirusTotal</a>
                    <a href="https://urlscan.io/domain/${ioc}" target="_blank">URLScan.io</a>
                    <a href="https://mxtoolbox.com/SuperTool.aspx?action=mx%3a${ioc}" target="_blank">MXToolbox</a>
                `;
                break;
            case 'Hash MD5':
            case 'Hash SHA1':
            case 'Hash SHA256':
                linksHtml = `
                    <a href="https://www.virustotal.com/gui/file/${ioc}" target="_blank">VirusTotal</a>
                    <a href="https://bazaar.abuse.ch/browse.php?search=hash%3A${ioc}" target="_blank">MalwareBazaar</a>
                `;
                break;
            default:
                linksHtml = '<span>Nenhum link de análise automática para este tipo.</span>';
        }

        itemDiv.innerHTML = `
            <h3>${ioc} <span>${type}</span></h3>
            <div class="analysis-links">
                ${linksHtml}
            </div>
        `;
        return itemDiv;
    }
});