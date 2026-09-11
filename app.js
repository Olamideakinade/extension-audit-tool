/**
 * Extension & MCP Supply Chain Auditor - Core Application Logic
 * Version: v1.2.0
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
            "args": ["-m", "mcp_sql_server", "--dsn", "postgres://admin:secret@localhost:5432/prod"]
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
        },
        {
            "id": "risk.evaluator.plugin",
            "publisher": "community",
            "version": "0.1.9"
        }
    ]
};

class AuditEngine {
    constructor(manifest) {
        this.manifest = manifest;
        this.results = [];
        this.complianceScore = 100;
    }

    evaluate() {
        this.results = [];
        let deductions = 0;

        const mcpServers = this.manifest.mcpServers || {};
        for (const [name, config] of Object.entries(mcpServers)) {
            let risk = "LOW";
            let reasons = [];

            const argsStr = JSON.stringify(config.args || []);
            if (argsStr.includes("http://") || argsStr.includes("https://") || argsStr.includes("malicious")) {
                risk = "HIGH";
                reasons.push("Remote or external execution URL detected in command arguments.");
                deductions += 25;
            } else if (argsStr.includes("password") || argsStr.includes("secret") || argsStr.includes("dsn")) {
                risk = "MEDIUM";
                reasons.push("Potential credentials or connection strings exposed in arguments.");
                deductions += 15;
            } else {
                reasons.push("Standard local execution path.");
            }

            this.results.push({
                type: "MCP Server",
                name,
                publisher: config.command || "unknown",
                risk,
                reasons: reasons.join(" ")
            });
        }

        const extensions = this.manifest.extensions || [];
        extensions.forEach(ext => {
            let risk = "LOW";
            let reasons = [];

            if (ext.publisher === "unknown-publisher" || !ext.publisher) {
                risk = "HIGH";
                reasons.push("Unverified publisher identity.");
                deductions += 20;
            } else if (ext.version && ext.version.startsWith("0.")) {
                risk = "MEDIUM";
                reasons.push("Pre-release or experimental version numbering.");
                deductions += 10;
            } else {
                reasons.push("Verified publisher and stable release.");
            }

            this.results.push({
                type: "Extension",
                name: ext.id,
                publisher: ext.publisher,
                risk,
                reasons: reasons.join(" ")
            });
        });

        this.complianceScore = Math.max(0, 100 - deductions);
        return this.results;
    }

    getSummary() {
        const counts = { HIGH: 0, MEDIUM: 0, LOW: 0 };
        this.results.forEach(r => {
            if (counts[r.risk] !== undefined) counts[r.risk]++;
        });
        return {
            total: this.results.length,
            counts,
            complianceScore: this.complianceScore
        };
    }
}

let currentManifest = sampleManifest;
let currentFilter = "ALL";
let currentSearch = "";

function initApp() {
    const editor = document.getElementById("json-editor");
    if (editor) {
        editor.value = JSON.stringify(sampleManifest, null, 2);
    }

    runAudit();
    setupEventListeners();
}

function runAudit() {
    const editor = document.getElementById("json-editor");
    try {
        const parsed = JSON.parse(editor.value);
        currentManifest = parsed;
        const engine = new AuditEngine(currentManifest);
        engine.evaluate();
        renderDashboard(engine);
        clearError();
    } catch (err) {
        showError("Invalid JSON manifest format: " + err.message);
    }
}

function renderDashboard(engine) {
    const summary = engine.getSummary();
    
    document.getElementById("stat-total").textContent = summary.total;
    document.getElementById("stat-high").textContent = summary.counts.HIGH;
    document.getElementById("stat-med").textContent = summary.counts.MEDIUM;
    document.getElementById("stat-low").textContent = summary.counts.LOW;
    document.getElementById("stat-compliance").textContent = summary.complianceScore + "%";

    const tbody = document.getElementById("audit-results-body");
    tbody.innerHTML = "";

    const filtered = engine.results.filter(item => {
        const matchesFilter = currentFilter === "ALL" || item.risk === currentFilter;
        const matchesSearch = item.name.toLowerCase().includes(currentSearch.toLowerCase()) ||
                              item.publisher.toLowerCase().includes(currentSearch.toLowerCase());
        return matchesFilter && matchesSearch;
    });

    if (filtered.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" class="no-results">No matching audit findings found.</td></tr>`;
        return;
    }

    filtered.forEach(item => {
        const tr = document.createElement("tr");
        const badgeClass = `badge-${item.risk.toLowerCase()}`;
        tr.innerHTML = `
            <td><span class="type-tag">${item.type}</span></td>
            <td><code>${item.name}</code></td>
            <td>${item.publisher}</td>
            <td><span class="risk-badge ${badgeClass}">${item.risk}</span></td>
            <td class="reason-text">${item.reasons}</td>
        `;
        tbody.appendChild(tr);
    });
}

function showError(msg) {
    let banner = document.getElementById("error-banner");
    if (!banner) {
        banner = document.createElement("div");
        banner.id = "error-banner";
        banner.className = "error-banner";
        document.querySelector(".dashboard").prepend(banner);
    }
    banner.textContent = msg;
}

function clearError() {
    const banner = document.getElementById("error-banner");
    if (banner) banner.remove();
}

function setupEventListeners() {
    document.getElementById("run-audit-btn").addEventListener("click", runAudit);
    document.getElementById("load-sample-btn").addEventListener("click", () => {
        document.getElementById("json-editor").value = JSON.stringify(sampleManifest, null, 2);
        runAudit();
    });

    document.getElementById("search-input").addEventListener("input", (e) => {
        currentSearch = e.target.value;
        runAudit();
    });

    document.querySelectorAll(".filter-btn").forEach(btn => {
        btn.addEventListener("click", (e) => {
            document.querySelectorAll(".filter-btn").forEach(b => b.classList.remove("active"));
            e.target.classList.add("active");
            currentFilter = e.target.getAttribute("data-filter");
            runAudit();
        });
    });

    document.getElementById("export-json-btn").addEventListener("click", () => {
        exportFile("application/json", JSON.stringify(currentManifest, null, 2), "audit-manifest.json");
    });

    document.getElementById("export-csv-btn").addEventListener("click", () => {
        const engine = new AuditEngine(currentManifest);
        engine.evaluate();
        let csv = "Type,Name,Publisher,Risk,Reasons\n";
        engine.results.forEach(r => {
            csv += `"${r.type}","${r.name}","${r.publisher}","${r.risk}","${r.reasons}"\n`;
        });
        exportFile("text/csv", csv, "audit-report.csv");
    });

    document.getElementById("export-html-btn").addEventListener("click", () => {
        const engine = new AuditEngine(currentManifest);
        engine.evaluate();
        const summary = engine.getSummary();
        let html = `<!DOCTYPE html><html><head><title>Audit Report</title><style>body{font-family:sans-serif;padding:20px;}table{width:100%;border-collapse:collapse;}th,td{border:1px solid #ccc;padding:8px;text-align:left;}</style></head><body>`;
        html += `<h1>Supply Chain Audit Report</h1><p>Compliance Score: ${summary.complianceScore}%</p>`;
        html += `<table><tr><th>Type</th><th>Name</th><th>Publisher</th><th>Risk</th><th>Reasons</th></tr>`;
        engine.results.forEach(r => {
            html += `<tr><td>${r.type}</td><td>${r.name}</td><td>${r.publisher}</td><td>${r.risk}</td><td>${r.reasons}</td></tr>`;
        });
        html += `</table></body></html>`;
        exportFile("text/html", html, "audit-report.html");
    });

    window.addEventListener("keydown", (e) => {
        if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
            e.preventDefault();
            runAudit();
        }
    });
}

function exportFile(mimeType, content, filename) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

document.addEventListener("DOMContentLoaded", initApp);
