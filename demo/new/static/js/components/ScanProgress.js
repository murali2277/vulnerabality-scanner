export class ScanProgress {
    constructor(elementId) {
        this.element = document.getElementById(elementId);
        this.interval = null;
    }

    start() {
        this.updateProgress(0);
        this.simulateProgress();
    }

    stop() {
        if (this.interval) {
            clearInterval(this.interval);
            this.interval = null;
        }
        this.updateProgress(100);
    }

    updateProgress(value) {
        this.element.style.width = `${value}%`;
    }

    simulateProgress() {
        let progress = 0;
        this.interval = setInterval(() => {
            progress += Math.random() * 15;
            if (progress > 90) {
                clearInterval(this.interval);
                this.interval = null;
                return;
            }
            this.updateProgress(progress);
        }, 500);
    }
}