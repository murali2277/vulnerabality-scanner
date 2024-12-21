export class LoadingOverlay {
    constructor(elementId) {
        this.element = document.getElementById(elementId);
    }

    show() {
        this.element.classList.add('show');
    }

    hide() {
        this.element.classList.remove('show');
    }
}