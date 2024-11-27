import { validateUrl, validateChecks } from '../utils/validation.js';

export class ScannerService {
    async scan(url, checks) {
        if (!validateUrl(url)) {
            throw new Error('Invalid URL format');
        }

        if (!validateChecks(checks)) {
            throw new Error('No security checks selected');
        }

        const response = await fetch('/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url, checks }),
        });

        if (!response.ok) {
            throw new Error('Scan failed. Please try again.');
        }

        return response.json();
    }
}