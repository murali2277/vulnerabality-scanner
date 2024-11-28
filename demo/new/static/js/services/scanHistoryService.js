import { StorageService } from './storageService.js';

export class ScanHistoryService {
    constructor() {
        this.storageService = new StorageService();
    }

    async getHistory(page, itemsPerPage, sortField, sortDirection, filters) {
        try {
            return await this.storageService.filterHistory(
                filters,
                page,
                itemsPerPage,
                sortField,
                sortDirection
            );
        } catch (error) {
            throw new Error('Failed to load scan history: ' + error.message);
        }
    }

    async getScanDetails(scanId) {
        try {
            const scan = await this.storageService.getScanDetails(scanId);
            if (!scan) {
                throw new Error('Scan not found');
            }
            return scan;
        } catch (error) {
            throw new Error('Failed to load scan details: ' + error.message);
        }
    }

    async deleteScan(scanId) {
        try {
            const success = await this.storageService.deleteScan(scanId);
            if (!success) {
                throw new Error('Failed to delete scan');
            }
            return { success: true };
        } catch (error) {
            throw new Error('Failed to delete scan: ' + error.message);
        }
    }
}