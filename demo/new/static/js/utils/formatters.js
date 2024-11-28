export function formatDate(dateString) {
    const date = new Date(dateString);
    return new Intl.DateTimeFormat('en-US', {
        year: 'numeric',
        month: 'short',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    }).format(date);
}

export function truncateUrl(url) {
    const maxLength = 50;
    return url.length > maxLength ? url.substring(0, maxLength) + '...' : url;
}