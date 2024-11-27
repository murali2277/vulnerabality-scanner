import { Toast } from './utils/toast.js';
import { LoadingOverlay } from './components/LoadingOverlay.js';
import { ScanProgress } from './components/ScanProgress.js';
import { ScannerService } from './services/scannerService.js';
import { ResultsView } from './views/ResultsView.js';

class SecurityScannerApp {
    constructor() {
        this.form = document.getElementById('scanForm');
        this.urlInput = document.getElementById('targetUrl');
        this.scanButton = document.getElementById('scanButton');
        
        this.toast = new Toast('toast');
        this.loadingOverlay = new LoadingOverlay('loadingOverlay');
        this.scanProgress = new ScanProgress('scanProgress');
        this.resultsView = new ResultsView('resultsContainer');
        this.scannerService = new ScannerService();
     

        this.isScanning = false;
        this.initialize();
    }

    initialize() {
        this.form.addEventListener('submit', (e) => this.handleSubmit(e));
    }

    async handleSubmit(e) {
        e.preventDefault();
        
        if (this.isScanning) return;
        
        const url = this.urlInput.value.trim();
        if (!url) return;

        const selectedChecks = Array.from(
            document.querySelectorAll('input[name="checks"]:checked')
        ).map(checkbox => checkbox.value);

        try {
            this.startScan();
            const data = await this.scannerService.scan(url, selectedChecks);
            this.resultsView.render(data);
            this.toast.show('Scan completed successfully!', 'success');
        } catch (err) {
            this.toast.show(err.message, 'error');
            this.resultsView.clear();
        } finally {
            this.endScan();
        }
    }

    startScan() {
        this.isScanning = true;
        this.scanButton.disabled = true;
        this.loadingOverlay.show();
        this.scanProgress.start();
    }

    endScan() {
        this.isScanning = false;
        this.scanButton.disabled = false;
        this.loadingOverlay.hide();
        this.scanProgress.stop();
    }
}

// Initialize the application
document.addEventListener('DOMContentLoaded', () => {
    new SecurityScannerApp();
});