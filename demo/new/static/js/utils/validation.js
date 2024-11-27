export function validateUrl(url) {
    try {
        new URL(url);
        return true;
    } catch {
        return false;
    }
}

export function validateChecks(checks) {
    return checks && checks.length > 0;
}