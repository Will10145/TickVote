
function logUserInteraction(action, data = {}) {
    // Only log if analytics cookies are enabled
    const cookiePreferences = getCookiePreferences();
    if (cookiePreferences && cookiePreferences.analytics) {
        fetch('/api/log-interaction', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                action: action,
                data: data,
                timestamp: new Date().toISOString()
            })
        }).catch(err => {
            console.debug('Analytics logging failed:', err);
        });
    }
}

// Helper function to get cookie preferences
function getCookiePreferences() {
    const preferencesStr = getCookie('cookiePreferences');
    if (preferencesStr) {
        try {
            return JSON.parse(preferencesStr);
        } catch (e) {
            return null;
        }
    }
    return null;
}

// Helper function to get cookie value
function getCookie(name) {
    const nameEQ = name + "=";
    const ca = document.cookie.split(';');
    for (let i = 0; i < ca.length; i++) {
        let c = ca[i];
        while (c.charAt(0) === ' ') c = c.substring(1, c.length);
        if (c.indexOf(nameEQ) === 0) return c.substring(nameEQ.length, c.length);
    }
    return null;
}

// Log page views for analytics (only if consent given)
document.addEventListener('DOMContentLoaded', function() {
    // Small delay to ensure cookie consent is processed
    setTimeout(function() {
        logUserInteraction('page_view', {
            page: window.location.pathname,
            referrer: document.referrer
        });
    }, 1000);
});

// Log poll interactions
function logPollInteraction(action, pollData) {
    logUserInteraction('poll_' + action, pollData);
}
