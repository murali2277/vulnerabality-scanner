export class ResultsView {
    constructor(containerId) {
        this.container = document.getElementById(containerId);
    }

    render(data) {
        if (!data || !data[0]) {
            this.clear();
            return;
        }

        const results = data[0];
        const checks = results.checks;
        
        this.container.innerHTML = this.generateHTML(results);
        this.container.classList.add('show');
    }

    clear() {
        this.container.innerHTML = '';
        this.container.classList.remove('show');
    }

    generateHTML(results) {
       const stats = this.generateStats(results.checks);
       // const stats = this.displaySummaryStats(results.checks);
        const checksList = this.generateChecksList(results.checks);

        return `
            <div class="results-header">
                <h2>Scan Results</h2>
                <div class="scan-info">
                    <p>Target URL: ${results.target_url}</p>
                    <p>Scan Time: ${new Date(results.scan_time).toLocaleString()}</p>
                </div>
            </div>
            ${stats}
            ${checksList}
        `;
    }

    generateStats(checks) {
        const counts = {
            total: Object.keys(checks).length,
            safe: 0,
            warning: 0,
            danger: 0
        };

        Object.values(checks).forEach(check => {
            counts[check.status]++;
        });

        return `
            <div class="summary-stats">
            <div class="stat-card">
                    <div class="stat-value">${counts.total}</div>
                    <div class="stat-label">Total Checks</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">${counts.safe}</div>
                    <div class="stat-label">Passed</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">${counts.warning}</div>
                    <div class="stat-label">Warnings</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">${counts.danger}</div>
                    <div class="stat-label">Critical</div>
                </div>
            </div>
        `;
    }
    

    generateChecksList(checks) {
        return Object.entries(checks).map(([key, check]) => `
            <div class="result-card">
                <div class="check-header">
                    <span class="status-indicator status-${check.status}"></span>
                    <span class="check-name">${check.name}</span>
                </div>
                ${check.findings && check.findings.length > 0 ? `
                    <ul class="details-list"> 
                        ${check.findings.map(finding => `
                            <li class="finding-item">${finding.detail}</li>
                        `).join('')}
                    </ul>
                ` : '<p class="details-list">No issues found</p>'}
            </div>
        `).join('');
    }
   

}