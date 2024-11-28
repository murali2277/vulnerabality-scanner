export class Modal {
    constructor(modalId) {
        this.modal = document.getElementById(modalId);
        this.modalContent = this.modal.querySelector('.modal-content');
        this.closeBtn = this.modal.querySelector('.close-btn');
        
        this.closeBtn.addEventListener('click', () => this.close());
        this.modal.addEventListener('click', (e) => {
            if (e.target === this.modal) {
                this.close();
            }
        });
    }

    open() {
        this.modal.style.display = 'block';
        document.body.style.overflow = 'hidden';
    }

    close() {
        this.modal.style.display = 'none';
        document.body.style.overflow = 'auto';
    }

    setContent(html) {
        this.modalContent.querySelector('.modal-body').innerHTML = html;
    }
}