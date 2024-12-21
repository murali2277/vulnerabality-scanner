class HelpCenter {
    constructor() {
        this.searchInput = document.getElementById('searchHelp');
        this.navItems = document.querySelectorAll('.help-nav-item');
        this.sections = document.querySelectorAll('.help-section');
        
        this.initialize();
    }

    initialize() {
        // Handle navigation
        this.navItems.forEach(item => {
            item.addEventListener('click', (e) => {
                e.preventDefault();
                const targetId = item.getAttribute('href').substring(1);
                this.showSection(targetId);
            });
        });

        // Handle search
        this.searchInput.addEventListener('input', (e) => {
            this.handleSearch(e.target.value);
        });

        // Handle deep linking
        if (window.location.hash) {
            const sectionId = window.location.hash.substring(1);
            this.showSection(sectionId);
        }
    }

    showSection(sectionId) {
        // Update navigation
        this.navItems.forEach(item => {
            item.classList.remove('active');
            if (item.getAttribute('href') === `#${sectionId}`) {
                item.classList.add('active');
            }
        });

        // Update sections
        this.sections.forEach(section => {
            section.classList.remove('active');
            if (section.id === sectionId) {
                section.classList.add('active');
            }
        });

        // Update URL without scrolling
        history.pushState(null, null, `#${sectionId}`);
    }

    handleSearch(query) {
        const searchTerm = query.toLowerCase();
        
        if (!searchTerm) {
            // Show all sections if search is empty
            this.sections.forEach(section => {
                section.style.display = 'none';
                if (section.classList.contains('active')) {
                    section.style.display = 'block';
                }
            });
            return;
        }

        // Show sections that match the search
        this.sections.forEach(section => {
            const content = section.textContent.toLowerCase();
            section.style.display = content.includes(searchTerm) ? 'block' : 'none';
        });
    }
}

// Initialize the help center when the page loads
document.addEventListener('DOMContentLoaded', () => {
    new HelpCenter();
});