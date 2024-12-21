export class Toast {
    constructor(elementId) {
        this.element = document.getElementById(elementId);
        this.timeoutId = null;
    }

    show(message, type = 'info', duration = 3000) {
        if (this.timeoutId) {
            clearTimeout(this.timeoutId);
        }

        this.element.textContent = message;
        this.element.className = `toast show ${type}`;
        
        this.timeoutId = setTimeout(() => {
            this.hide();
        }, duration);
    }

    hide() {
        this.element.classList.remove('show');
    }
}