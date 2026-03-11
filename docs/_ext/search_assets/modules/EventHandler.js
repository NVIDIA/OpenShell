/**
 * EventHandler Module
 * Handles keyboard shortcuts and event management for the search interface
 */

class EventHandler {
    constructor(enhancedSearch) {
        this.enhancedSearch = enhancedSearch;
        this.searchInterface = enhancedSearch.searchInterface;
        this.resultRenderer = enhancedSearch.resultRenderer;
        this.searchEngine = enhancedSearch.searchEngine;
        this.utils = enhancedSearch.utils;

        // Track bound event listeners for cleanup
        this.boundListeners = new Map();

        // Debounced search function
        this.debouncedSearch = this.utils.debounce(this.handleSearch.bind(this), 200);
    }

    /**
     * Bind all event listeners
     */
    bindEvents() {
        this.bindInputEvents();
        this.bindModalEvents();
        this.bindGlobalEvents();
        console.log('✅ Event handlers bound');
    }

    /**
     * Bind input-related events
     */
    bindInputEvents() {
        const input = this.searchInterface.getInput();
        if (!input) return;

        // Search input
        const inputHandler = (e) => this.debouncedSearch(e);
        input.addEventListener('input', inputHandler);
        this.boundListeners.set('input', inputHandler);

        // Keyboard navigation
        const keydownHandler = (e) => this.handleKeyDown(e);
        input.addEventListener('keydown', keydownHandler);
        this.boundListeners.set('keydown', keydownHandler);
    }

    /**
     * Bind page-specific events (replaces modal events)
     */
    bindModalEvents() {
        // Check if we're on the search page
        if (!this.searchInterface.isSearchPage()) {
            return;
        }

        // Get query parameter if we're on search page
        const urlParams = new URLSearchParams(window.location.search);
        const query = urlParams.get('q');

        if (query) {
            // Perform search immediately with the query from URL
            setTimeout(() => {
                const input = this.searchInterface.getInput();
                if (input) {
                    input.value = query;
                    this.handleSearch({ target: input });
                }
            }, 100);
        }
    }

    /**
     * Bind global keyboard shortcuts
     */
    bindGlobalEvents() {
        const globalKeyHandler = (e) => {
            // Ctrl+K or Cmd+K to focus search input
            if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
                e.preventDefault();
                // Focus the search input if we're on the search page
                const searchInput = this.searchInterface.getInput();
                if (searchInput) {
                    searchInput.focus();
                } else {
                    // If not on search page, redirect to search page
                    window.location.href = 'search.html';
                }
                return;
            }
        };

        document.addEventListener('keydown', globalKeyHandler);
        this.boundListeners.set('global', globalKeyHandler);
    }

    /**
     * Handle search input
     */
    async handleSearch(event) {
        const query = event.target.value.trim();
        const resultsContainer = this.searchInterface.getResultsContainer();

        if (query.length < this.enhancedSearch.options.minQueryLength) {
            this.searchInterface.showEmptyState();
            this.searchInterface.clearStats();
            return;
        }

        try {
            // Show loading state
            this.resultRenderer.renderLoading(resultsContainer);

            // Perform search
            const results = this.searchEngine.search(query, this.enhancedSearch.options.maxResults);
            const count = results.length;

            // Render results
            this.resultRenderer.render(results, query, resultsContainer);

            // Update stats
            this.searchInterface.updateStats(query, count);

            // Emit search event for AI Assistant extension if available
            this.emitSearchEvent(query, results, count);

        } catch (error) {
            console.error('Search error:', error);
            this.resultRenderer.renderError(resultsContainer, 'Search temporarily unavailable');
            this.searchInterface.clearStats();
        }
    }

    /**
     * Handle keyboard navigation
     */
    handleKeyDown(event) {
        const resultsContainer = this.searchInterface.getResultsContainer();

        switch (event.key) {
            case 'ArrowDown':
                event.preventDefault();
                this.resultRenderer.selectNext(resultsContainer);
                break;

            case 'ArrowUp':
                event.preventDefault();
                this.resultRenderer.selectPrevious(resultsContainer);
                break;

            case 'Enter':
                event.preventDefault();
                this.resultRenderer.activateSelected(resultsContainer);
                break;

            case 'Escape':
                event.preventDefault();
                this.enhancedSearch.hide();
                break;
        }
    }

    /**
     * Emit search event for other extensions
     */
    emitSearchEvent(query, results, count) {
        if (window.AIAssistant && window.aiAssistantInstance) {
            const searchEvent = new CustomEvent('enhanced-search-results', {
                detail: { query, results, count }
            });
            document.dispatchEvent(searchEvent);
        }
    }

    /**
     * Handle window resize
     */
    handleResize() {
        // Adjust modal positioning if needed
        const modal = this.searchInterface.getModal();
        if (modal && this.searchInterface.isModalVisible()) {
            // Could add responsive adjustments here
        }
    }

    /**
     * Handle focus management
     */
    handleFocus(event) {
        // Trap focus within modal when visible
        if (this.searchInterface.isModalVisible()) {
            const modal = this.searchInterface.getModal();
            const focusableElements = modal.querySelectorAll(
                'button, input, select, textarea, [tabindex]:not([tabindex="-1"])'
            );

            const firstFocusable = focusableElements[0];
            const lastFocusable = focusableElements[focusableElements.length - 1];

            if (event.key === 'Tab') {
                if (event.shiftKey) {
                    // Shift + Tab
                    if (document.activeElement === firstFocusable) {
                        event.preventDefault();
                        lastFocusable.focus();
                    }
                } else {
                    // Tab
                    if (document.activeElement === lastFocusable) {
                        event.preventDefault();
                        firstFocusable.focus();
                    }
                }
            }
        }
    }

    /**
     * Bind additional event listeners
     */
    bindAdditionalEvents() {
        // Window resize
        const resizeHandler = this.utils.debounce(() => this.handleResize(), 100);
        window.addEventListener('resize', resizeHandler);
        this.boundListeners.set('resize', resizeHandler);

        // Focus trap
        const focusHandler = (e) => this.handleFocus(e);
        document.addEventListener('keydown', focusHandler);
        this.boundListeners.set('focus', focusHandler);
    }

    /**
     * Unbind all event listeners
     */
    unbindEvents() {
        // Remove input events
        const input = this.searchInterface.getInput();
        if (input && this.boundListeners.has('input')) {
            input.removeEventListener('input', this.boundListeners.get('input'));
            input.removeEventListener('keydown', this.boundListeners.get('keydown'));
        }

        // Remove modal events
        const closeBtn = this.searchInterface.getCloseButton();
        if (closeBtn && this.boundListeners.has('close')) {
            closeBtn.removeEventListener('click', this.boundListeners.get('close'));
        }

        const backdrop = this.searchInterface.getBackdrop();
        if (backdrop && this.boundListeners.has('backdrop')) {
            backdrop.removeEventListener('click', this.boundListeners.get('backdrop'));
        }

        // Remove global events
        if (this.boundListeners.has('global')) {
            document.removeEventListener('keydown', this.boundListeners.get('global'));
        }

        if (this.boundListeners.has('resize')) {
            window.removeEventListener('resize', this.boundListeners.get('resize'));
        }

        if (this.boundListeners.has('focus')) {
            document.removeEventListener('keydown', this.boundListeners.get('focus'));
        }

        // Clear listeners map
        this.boundListeners.clear();

        console.log('✅ Event handlers unbound');
    }

    /**
     * Get event handler statistics
     */
    getStatistics() {
        return {
            boundListeners: this.boundListeners.size,
            modalVisible: this.searchInterface.isModalVisible(),
            hasInput: !!this.searchInterface.getInput(),
            hasModal: !!this.searchInterface.getModal()
        };
    }

    /**
     * Check if events are properly bound
     */
    isReady() {
        return this.boundListeners.size > 0 &&
               this.searchInterface.getInput() !== null &&
               this.searchInterface.getModal() !== null;
    }
}

// Make EventHandler available globally
window.EventHandler = EventHandler;
