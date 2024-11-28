export class StorageService {
    constructor() {
        this.STORAGE_KEY = 'security_scanner_history';
    }

    async getScanHistory() {
        try {
            const history = localStorage.getItem(this.STORAGE_KEY);
            return history ? JSON.parse(history) : [];
        } catch (error) {
            console.error('Failed to get scan history:', error);
            return [];
        }
    }

    async saveScanResult(scanResult) {
        try {
            const history = await this.getScanHistory();
            history.unshift({
                id: Date.now().toString(),
                ...scanResult
            });
            
            // Keep only the last 100 scans
            const trimmedHistory = history.slice(0, 100);
            localStorage.setItem(this.STORAGE_KEY, JSON.stringify(trimmedHistory));
            
            return true;
        } catch (error) {
            console.error('Failed to save scan result:', error);
            return false;
        }
    }

    async deleteScan(scanId) {
        try {
            const history = await this.getScanHistory();
            const updatedHistory = history.filter(scan => scan.id !== scanId);
            localStorage.setItem(this.STORAGE_KEY, JSON.stringify(updatedHistory));
            return true;
        } catch (error) {
            console.error('Failed to delete scan:', error);
            return false;
        }
    }

    async getScanDetails(scanId) {
        try {
            const history = await this.getScanHistory();
            return history.find(scan => scan.id === scanId);
        } catch (error) {
            console.error('Failed to get scan details:', error);
            return null;
        }
    }

    async filterHistory(filters, page, itemsPerPage, sortField, sortDirection) {
        try {
            let history = await this.getScanHistory();

            // Apply filters
            if (filters.search) {
                const searchTerm = filters.search.toLowerCase();
                history = history.filter(scan => 
                    scan.target_url.toLowerCase().includes(searchTerm)
                );
            }

            if (filters.status) {
                history = history.filter(scan => 
                    this.getOverallStatus(scan) === filters.status
                );
            }

            if (filters.date) {
                const cutoffDate = this.getDateCutoff(filters.date);
                history = history.filter(scan => 
                    new Date(scan.scan_time) >= cutoffDate
                );
            }

            // Apply sorting
            history.sort((a, b) => {
                let comparison = 0;
                switch (sortField) {
                    case 'date':
                        comparison = new Date(b.scan_time) - new Date(a.scan_time);
                        break;
                    case 'url':
                        comparison = a.target_url.localeCompare(b.target_url);
                        break;
                    case 'status':
                        comparison = this.getOverallStatus(a).localeCompare(this.getOverallStatus(b));
                        break;
                }
                return sortDirection === 'asc' ? comparison : -comparison;
            });

            // Calculate pagination
            const totalItems = history.length;
            const totalPages = Math.ceil(totalItems / itemsPerPage);
            const startIndex = (page - 1) * itemsPerPage;
            const items = history.slice(startIndex, startIndex + itemsPerPage);

            return {
                items,
                totalPages,
                currentPage: page,
                totalItems
            };
        } catch (error) {
            console.error('Failed to filter history:', error);
            return {
                items: [],
                totalPages: 1,
                currentPage: 1,
                totalItems: 0
            };
        }
    }

    getOverallStatus(scan) {
        if (Object.values(scan.checks).some(check => check.status === 'danger')) {
            return 'danger';
        }
        if (Object.values(scan.checks).some(check => check.status === 'warning')) {
            return 'warning';
        }
        return 'safe';
    }

    getDateCutoff(dateFilter) {
        const now = new Date();
        switch (dateFilter) {
            case '24h':
                return new Date(now - 24 * 60 * 60 * 1000);
            case '7d':
                return new Date(now - 7 * 24 * 60 * 60 * 1000);
            case '30d':
                return new Date(now - 30 * 24 * 60 * 60 * 1000);
            default:
                return new Date(0);
        }
    }
}