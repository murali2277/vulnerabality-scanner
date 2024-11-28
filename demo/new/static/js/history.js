class HistoryManager {
    constructor() {
        this.historyContainer = document.getElementById('historyContainer');
        this.loadHistory();
    }

    loadHistory() {
        const history = this.getScanHistory();
        if (history.length === 0) {
            this.showEmptyState();
        } else {
            this.renderHistory(history);
        }
    }

    getScanHistory() {
        const saved = localStorage.getItem('security_scanner_history');
        return saved ? JSON.parse(saved) : [];
    }

    showEmptyState() {
        this.historyContainer.innerHTML = `
            <div class="empty-state">
                No scan history available yet. Start by running a new scan.
            </div>
        `;
    }

    formatTimeAgo(timestamp) {
        const date = new Date(timestamp);
        const now = new Date();
        const seconds = Math.floor((now - date) / 1000);
        
        const intervals = {
            year: 31536000,
            month: 2592000,
            week: 604800,
            day: 86400,
            hour: 3600,
            minute: 60
        };

        for (const [unit, secondsInUnit] of Object.entries(intervals)) {
            const interval = Math.floor(seconds / secondsInUnit);
            if (interval >= 1) {
                return `${interval} ${unit}${interval === 1 ? '' : 's'} ago`;
            }
        }

        return 'Just now';
    }

    calculateSeverity(checks) {
        const severity = { critical: 0, warning: 0, safe: 0 };
        Object.values(checks).forEach(check => {
            if (check.status === 'danger') severity.critical++;
            else if (check.status === 'warning') severity.warning++;
            else severity.safe++;
        });
        return severity;
    }

    renderHistory(history) {
        this.historyContainer.innerHTML = history.map(scan => {
            const severity = this.calculateSeverity(scan.checks);
            
            return `
                <div class="scan-card">
                    <div class="scan-header">
                        <div>
                            <div class="scan-url">${scan.target_url}</div>
                            <div class="scan-timestamp">${this.formatTimeAgo(scan.scan_time)}</div>
                        </div>
                        <div class="scan-stats">
                            <div class="stat-item">
                                <div class="stat-value critical">${severity.critical}</div>
                                <div class="stat-label">Critical</div>
                            </div>
                            <div class="stat-item">
                                <div class="stat-value warning">${severity.warning}</div>
                                <div class="stat-label">Warnings</div>
                            </div>
                            <div class="stat-item">
                                <div class="stat-value safe">${severity.safe}</div>
                                <div class="stat-label">Passed</div>
                            </div>
                        </div>
                    </div>
                    <div class="results-grid">
                        ${Object.entries(scan.checks).map(([key, check]) => `
                            <div class="result-item">
                                <div class="result-header">
                                    <div class="status-indicator status-${check.status}"></div>
                                    <div>${check.name}</div>
                                </div>
                                <div class="result-details">
                                    ${check.findings && check.findings.length > 0 
                                        ? check.findings.slice(0, 2).map(finding => `
                                            <div>${finding.detail}</div>
                                        `).join('')
                                        : 'No issues found'
                                    }
                                </div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;
        }).join('');
    }
}

// Initialize the history manager when the page loads
document.addEventListener('DOMContentLoaded', () => {
    new HistoryManager();
});