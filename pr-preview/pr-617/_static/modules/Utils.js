/**
 * Utils Module
 * Contains utility functions used across the enhanced search system
 */

class Utils {
    constructor() {
        // Utility class - no initialization needed
    }

    /**
     * Debounce function to limit rapid function calls
     */
    debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }

    /**
     * Escape special regex characters
     */
    escapeRegex(string) {
        return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }

    /**
     * Escape HTML to prevent XSS attacks
     */
    escapeHtml(unsafe) {
        return unsafe
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    /**
     * Highlight search terms in text
     */
    highlightText(text, query, highlightClass = 'search-highlight') {
        if (!query || !text) return text;

        const terms = query.toLowerCase().split(/\s+/);
        let highlighted = text;

        terms.forEach(term => {
            if (term.length > 1) {
                const regex = new RegExp(`(${this.escapeRegex(term)})`, 'gi');
                highlighted = highlighted.replace(regex, `<mark class="${highlightClass}">$1</mark>`);
            }
        });

        return highlighted;
    }

    /**
     * Generate breadcrumb from document ID
     */
    generateBreadcrumb(docId) {
        const parts = docId.split('/').filter(part => part && part !== 'index');
        return parts.length > 0 ? parts.join(' › ') : 'Home';
    }

    /**
     * Generate anchor link from heading text (Sphinx-style)
     */
    generateAnchor(headingText) {
        return headingText
            .toLowerCase()
            .replace(/[^\w\s-]/g, '')  // Remove special chars
            .replace(/\s+/g, '-')      // Replace spaces with hyphens
            .trim();
    }

    /**
     * Get document URL from result object
     */
    getDocumentUrl(result) {
        if (result.url) {
            return result.url;
        }
        return `${result.id.replace(/^\/+/, '')}.html`;
    }

    /**
     * Get appropriate icon for section type
     */
    getSectionIcon(type, level) {
        switch (type) {
            case 'title':
                return '<i class="fa-solid fa-file-lines section-icon title-icon"></i>';
            case 'heading':
                if (level <= 2) return '<i class="fa-solid fa-heading section-icon h1-icon"></i>';
                if (level <= 4) return '<i class="fa-solid fa-heading section-icon h2-icon"></i>';
                return '<i class="fa-solid fa-heading section-icon h3-icon"></i>';
            case 'content':
                return '<i class="fa-solid fa-align-left section-icon content-icon"></i>';
            default:
                return '<i class="fa-solid fa-circle section-icon"></i>';
        }
    }

    /**
     * Load external script (like Lunr.js)
     */
    async loadScript(src) {
        return new Promise((resolve, reject) => {
            const script = document.createElement('script');
            script.src = src;
            script.onload = resolve;
            script.onerror = reject;
            document.head.appendChild(script);
        });
    }

    /**
     * Safe substring with fallback
     */
    safeSubstring(str, maxLength = 200, fallback = '') {
        if (!str) return fallback;
        return str.length > maxLength ? str.substring(0, maxLength) : str;
    }

    /**
     * Check if string is valid and not empty
     */
    isValidString(str) {
        return typeof str === 'string' && str.trim().length > 0;
    }

    /**
     * Safe array access with fallback
     */
    safeArray(arr, fallback = []) {
        return Array.isArray(arr) ? arr : fallback;
    }
}

// Make Utils available globally
window.Utils = Utils;
