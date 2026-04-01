/**
 * SearchInterface Module
 * Handles the creation and management of the search UI
 */

class SearchInterface {
    constructor(options) {
        this.options = options;
        this.isVisible = false;
        this.modal = null;
        this.input = null;
        this.resultsContainer = null;
        this.statsContainer = null;
    }

    /**
     * Create the search interface elements
     */
    create() {
        // Check if we're on the search page
        if (this.isSearchPage()) {
            this.enhanceSearchPage();
        } else {
            // On other pages, create the modal for search functionality
            this.createModal();
            this.enhanceSearchButton();
        }
        console.log('✅ Search interface created');
    }

    /**
     * Check if we're on the search page
     */
    isSearchPage() {
        return window.location.pathname.includes('/search') ||
               window.location.pathname.includes('/search.html') ||
               window.location.pathname.endsWith('search/') ||
               document.querySelector('#search-results') !== null ||
               document.querySelector('.search-page') !== null ||
               document.querySelector('form[action*="search"]') !== null ||
               document.title.toLowerCase().includes('search') ||
               document.querySelector('h1')?.textContent.toLowerCase().includes('search');
    }

    /**
     * Enhance the existing search page using the template structure
     */
    enhanceSearchPage() {
        console.log('🔍 Enhancing search page using existing template...');
        console.log('📄 Page URL:', window.location.href);
        console.log('📋 Page title:', document.title);

        // Use the template's existing elements
        this.input = document.querySelector('#enhanced-search-page-input');
        this.resultsContainer = document.querySelector('#enhanced-search-page-results');

        console.log('🔎 Template search input found:', !!this.input);
        console.log('📦 Template results container found:', !!this.resultsContainer);

        if (this.input && this.resultsContainer) {
            console.log('✅ Using existing template structure - no additional setup needed');
            // The template's JavaScript will handle everything
            return;
        }

        // Fallback for non-template pages
        console.log('⚠️ Template elements not found, falling back to generic search page detection');
        this.fallbackToGenericSearchPage();
    }

    /**
     * Fallback for pages that don't use the template
     */
    fallbackToGenericSearchPage() {
        // Find existing search elements on generic pages
        this.input = document.querySelector('#searchbox input[type="text"]') ||
                    document.querySelector('input[name="q"]') ||
                    document.querySelector('.search input[type="text"]');

        // Find or create results container
        this.resultsContainer = document.querySelector('#search-results') ||
                               document.querySelector('.search-results') ||
                               this.createResultsContainer();

        // Create stats container
        this.statsContainer = this.createStatsContainer();

        // Hide default Sphinx search results if they exist
        this.hideDefaultResults();

        // Initialize with empty state
        this.showEmptyState();

        console.log('✅ Generic search page enhanced');
    }

    /**
     * Create results container if it doesn't exist
     */
    createResultsContainer() {
        const container = document.createElement('div');
        container.id = 'enhanced-search-results';
        container.className = 'enhanced-search-results';

        // Add basic styling to ensure proper positioning
        container.style.cssText = `
            width: 100%;
            max-width: none;
            margin: 1rem 0;
            clear: both;
            position: relative;
            z-index: 1;
        `;

        // Find the best place to insert it within the main content area
        const insertLocation = this.findBestInsertLocation();

        if (insertLocation.parent && insertLocation.method === 'append') {
            insertLocation.parent.appendChild(container);
            console.log(`✅ Results container added to: ${insertLocation.parent.className || insertLocation.parent.tagName}`);
        } else if (insertLocation.parent && insertLocation.method === 'after') {
            insertLocation.parent.insertAdjacentElement('afterend', container);
            console.log(`✅ Results container added after: ${insertLocation.parent.className || insertLocation.parent.tagName}`);
        } else {
            // Last resort - create a wrapper in main content
            this.createInMainContent(container);
        }

        return container;
    }

    /**
     * Find the best location to insert search results
     */
    findBestInsertLocation() {
        // Try to find existing search-related elements first
        let searchResults = document.querySelector('.search-results, #search-results');
        if (searchResults) {
            return { parent: searchResults, method: 'append' };
        }

        // Look for search form and place results after it
        let searchForm = document.querySelector('#searchbox, .search form, form[action*="search"]');
        if (searchForm) {
            return { parent: searchForm, method: 'after' };
        }

        // Look for main content containers (common Sphinx/theme classes)
        const mainSelectors = [
            '.document .body',
            '.document .documentwrapper',
            '.content',
            '.main-content',
            '.page-content',
            'main',
            '.container .row .col',
            '.rst-content',
            '.body-content'
        ];

        for (const selector of mainSelectors) {
            const element = document.querySelector(selector);
            if (element) {
                return { parent: element, method: 'append' };
            }
        }

        // Try to find any container that's not the body
        const anyContainer = document.querySelector('.container, .wrapper, .page, #content');
        if (anyContainer) {
            return { parent: anyContainer, method: 'append' };
        }

        return { parent: null, method: null };
    }

    /**
     * Create container in main content as last resort
     */
    createInMainContent(container) {
        // Create a wrapper section
        const wrapper = document.createElement('section');
        wrapper.className = 'search-page-content';
        wrapper.style.cssText = `
            max-width: 800px;
            margin: 2rem auto;
            padding: 0 1rem;
        `;

        // Add a title
        const title = document.createElement('h1');
        title.textContent = 'Search Results';
        title.style.cssText = 'margin-bottom: 1rem;';
        wrapper.appendChild(title);

        // Add the container
        wrapper.appendChild(container);

        // Insert into body, but with proper styling
        document.body.appendChild(wrapper);

        console.log('⚠️ Created search results in body with wrapper - consider improving page structure');
    }

    /**
     * Create stats container
     */
    createStatsContainer() {
        const container = document.createElement('div');
        container.className = 'enhanced-search-stats';
        container.style.cssText = 'margin: 1rem 0; font-size: 0.9rem; color: #666;';

        // Insert before results
        if (this.resultsContainer && this.resultsContainer.parentNode) {
            this.resultsContainer.parentNode.insertBefore(container, this.resultsContainer);
        }

        return container;
    }

    /**
     * Hide default Sphinx search results
     */
    hideDefaultResults() {
        // Hide default search results that Sphinx might show
        const defaultResults = document.querySelectorAll(
            '.search-summary, .search li, #search-results .search, .searchresults'
        );
        defaultResults.forEach(el => {
            el.style.display = 'none';
        });
    }

    /**
     * Create the main search modal (legacy - kept for compatibility)
     */
    createModal() {
        // Enhanced search modal
        const modal = document.createElement('div');
        modal.id = 'enhanced-search-modal';
        modal.className = 'enhanced-search-modal';
        modal.innerHTML = `
            <div class="enhanced-search-backdrop"></div>
            <div class="enhanced-search-container">
                <div class="enhanced-search-header">
                    <div class="enhanced-search-input-wrapper">
                        <i class="fa-solid fa-magnifying-glass search-icon"></i>
                        <input
                            type="text"
                            id="enhanced-search-input"
                            class="enhanced-search-input"
                            placeholder="${this.options.placeholder}"
                            autofocus
                        >
                        <button class="enhanced-search-close" title="Close search">
                            <i class="fa-solid fa-xmark"></i>
                        </button>
                    </div>
                    <div class="enhanced-search-stats"></div>
                </div>
                <div class="enhanced-search-results"></div>
                <div class="enhanced-search-footer">
                    <div class="enhanced-search-shortcuts">
                        <span><kbd>↵</kbd> Open</span>
                        <span><kbd>↑</kbd><kbd>↓</kbd> Navigate</span>
                        <span><kbd>Esc</kbd> Close</span>
                    </div>
                </div>
            </div>
        `;

        document.body.appendChild(modal);

        // Cache references
        this.modal = modal;
        this.input = modal.querySelector('#enhanced-search-input');
        this.resultsContainer = modal.querySelector('.enhanced-search-results');
        this.statsContainer = modal.querySelector('.enhanced-search-stats');

        // Add event handlers for closing the modal
        const closeButton = modal.querySelector('.enhanced-search-close');
        const backdrop = modal.querySelector('.enhanced-search-backdrop');

        if (closeButton) {
            closeButton.addEventListener('click', () => this.hideModal());
        }

        if (backdrop) {
            backdrop.addEventListener('click', () => this.hideModal());
        }

        // Hide modal by default
        modal.style.display = 'none';

        // Initialize with empty state
        this.showEmptyState();
    }

    /**
     * Replace or enhance existing search button to show modal
     */
    enhanceSearchButton() {
        // Find existing search button/form
        const searchForm = document.querySelector('#searchbox form') ||
                          document.querySelector('.search form') ||
                          document.querySelector('form[action*="search"]');

        if (searchForm) {
            // Prevent form submission and show modal instead
            searchForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.showModal();
            });
            console.log('✅ Search form enhanced to show modal');
        }

        // Find search button specifically and enhance it
        const existingButton = document.querySelector('.search-button-field, .search-button__button');
        if (existingButton) {
            existingButton.addEventListener('click', (e) => {
                e.preventDefault();
                this.showModal();
            });
            console.log('✅ Search button enhanced to show modal');
        }

        // Also look for search input fields and enhance them
        const searchInput = document.querySelector('#searchbox input[type="text"]') ||
                           document.querySelector('.search input[type="text"]');
        if (searchInput) {
            searchInput.addEventListener('focus', () => {
                this.showModal();
            });
            console.log('✅ Search input enhanced to show modal on focus');
        }
    }

    /**
     * Show the search interface (focus input or show modal)
     */
    show() {
        if (this.modal) {
            this.showModal();
        } else if (this.input) {
            this.input.focus();
            this.input.select();
        }
    }

    /**
     * Hide the search interface (hide modal or blur input)
     */
    hide() {
        if (this.modal) {
            this.hideModal();
        } else if (this.input) {
            this.input.blur();
        }
    }

    /**
     * Show the modal
     */
    showModal() {
        if (this.modal) {
            this.modal.style.display = 'flex';
            this.modal.classList.add('visible');
            this.isVisible = true;
            // Focus the input after a brief delay to ensure modal is visible
            setTimeout(() => {
                if (this.input) {
                    this.input.focus();
                    this.input.select();
                }
            }, 100);
            console.log('🔍 Search modal shown');
        }
    }

    /**
     * Hide the modal
     */
    hideModal() {
        if (this.modal) {
            this.modal.classList.remove('visible');
            this.isVisible = false;
            // Hide after animation completes
            setTimeout(() => {
                if (this.modal) {
                    this.modal.style.display = 'none';
                }
            }, 200);
            // Clear any search results
            this.showEmptyState();
            console.log('🔍 Search modal hidden');
        }
    }

    /**
     * Get the search input element
     */
    getInput() {
        return this.input;
    }

    /**
     * Get the results container
     */
    getResultsContainer() {
        return this.resultsContainer;
    }

    /**
     * Get the stats container
     */
    getStatsContainer() {
        return this.statsContainer;
    }

    /**
     * Get the modal element
     */
    getModal() {
        return this.modal;
    }

    /**
     * Check if modal is visible
     */
    isModalVisible() {
        return this.isVisible && this.modal && this.modal.style.display !== 'none';
    }

    /**
     * Show empty state in results
     */
    showEmptyState() {
        if (this.resultsContainer) {
            this.resultsContainer.innerHTML = `
                <div class="search-empty-state">
                    <i class="fa-solid fa-magnifying-glass"></i>
                    <p>Start typing to search documentation...</p>
                    <div class="search-tips">
                        <strong>Search tips:</strong>
                        <ul>
                            <li>Use specific terms for better results</li>
                            <li>Try different keywords if you don't find what you're looking for</li>
                            <li>Search includes titles, content, headings, and tags</li>
                        </ul>
                    </div>
                </div>
            `;
        }
    }

    /**
     * Show no results state
     */
    showNoResults(query) {
        if (this.resultsContainer) {
            this.resultsContainer.innerHTML = `
                <div class="search-no-results">
                    <i class="fa-solid fa-search-minus"></i>
                    <p>No results found for "<strong>${this.escapeHtml(query)}</strong>"</p>
                    <div class="search-suggestions">
                        <strong>Try:</strong>
                        <ul>
                            <li>Checking for typos</li>
                            <li>Using different or more general terms</li>
                            <li>Using fewer keywords</li>
                        </ul>
                    </div>
                </div>
            `;
        }
    }

    /**
     * Show error state
     */
    showError(message = 'Search temporarily unavailable') {
        if (this.resultsContainer) {
            this.resultsContainer.innerHTML = `
                <div class="search-error">
                    <i class="fa-solid fa-exclamation-triangle"></i>
                    <p>${this.escapeHtml(message)}</p>
                </div>
            `;
        }
    }

    /**
     * Update search statistics
     */
    updateStats(query, count) {
        if (this.statsContainer) {
            if (count > 0) {
                this.statsContainer.innerHTML = `${count} result${count !== 1 ? 's' : ''} for "${this.escapeHtml(query)}"`;
            } else {
                this.statsContainer.innerHTML = `No results for "${this.escapeHtml(query)}"`;
            }
        }
    }

    /**
     * Clear search statistics
     */
    clearStats() {
        if (this.statsContainer) {
            this.statsContainer.innerHTML = '';
        }
    }

    /**
     * Get current search query
     */
    getQuery() {
        return this.input ? this.input.value.trim() : '';
    }

    /**
     * Set search query
     */
    setQuery(query) {
        if (this.input) {
            this.input.value = query;
        }
    }

    /**
     * Clear search query
     */
    clearQuery() {
        if (this.input) {
            this.input.value = '';
        }
    }

    /**
     * Focus the search input
     */
    focusInput() {
        if (this.input) {
            this.input.focus();
        }
    }

    /**
     * Get close button for event binding
     */
    getCloseButton() {
        return this.modal ? this.modal.querySelector('.enhanced-search-close') : null;
    }

    /**
     * Get backdrop for event binding
     */
    getBackdrop() {
        return this.modal ? this.modal.querySelector('.enhanced-search-backdrop') : null;
    }

    /**
     * Escape HTML to prevent XSS
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
     * Add CSS class to modal
     */
    addModalClass(className) {
        if (this.modal) {
            this.modal.classList.add(className);
        }
    }

    /**
     * Remove CSS class from modal
     */
    removeModalClass(className) {
        if (this.modal) {
            this.modal.classList.remove(className);
        }
    }

    /**
     * Check if modal has class
     */
    hasModalClass(className) {
        return this.modal ? this.modal.classList.contains(className) : false;
    }

    /**
     * Destroy the search interface
     */
    destroy() {
        if (this.modal) {
            this.modal.remove();
            this.modal = null;
            this.input = null;
            this.resultsContainer = null;
            this.statsContainer = null;
        }
        this.isVisible = false;
    }
}

// Make SearchInterface available globally
window.SearchInterface = SearchInterface;
