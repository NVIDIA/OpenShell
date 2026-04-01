// Enhanced Search Bundle - Generated automatically
// Contains: Utils, DocumentLoader, SearchEngine, SearchInterface, ResultRenderer, EventHandler, SearchPageManager, main

// === Utils.js ===
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


// === DocumentLoader.js ===
/**
 * DocumentLoader Module
 * Handles loading and managing search documents from JSON index
 */

class DocumentLoader {
    constructor() {
        this.documents = {};
        this.isLoaded = false;
    }

    /**
     * Load documents from JSON index files
     */
    async loadDocuments() {
        try {
            const data = await this.fetchDocumentData();
            this.processDocuments(data);
            this.isLoaded = true;
            console.log(`✅ Document loader initialized with ${Object.keys(this.documents).length} documents`);
        } catch (error) {
            console.error('Failed to load search documents:', error);
            throw error;
        }
    }

    /**
     * Fetch document data from various possible paths
     */
    async fetchDocumentData() {
        // Try different paths to account for different page depths
        const possiblePaths = [
            './index.json',
            '../index.json',
            '../../index.json',
            '../../../index.json'
        ];

        for (const path of possiblePaths) {
            try {
                const response = await fetch(path);
                if (response.ok) {
                    const data = await response.json();
                    console.log(`✅ Loaded search index from: ${path}`);
                    return data;
                }
            } catch (error) {
                console.log(`❌ Failed to load from ${path}: ${error.message}`);
            }
        }

        throw new Error('Failed to load search data from any path');
    }

    /**
     * Process and filter documents from raw data
     * Supports three formats:
     * 1. Array of documents (new format): [{ id, title, ... }, ...]
     * 2. Object with children (legacy): { children: [...] }
     * 3. Single document (fallback): { id, title, ... }
     */
    processDocuments(data) {
        let allDocs;
        if (Array.isArray(data)) {
            // New format: root is an array of documents
            allDocs = data;
        } else if (data.children) {
            // Legacy format: object with children array
            allDocs = data.children;
        } else {
            // Fallback: single document
            allDocs = [data];
        }

        // Filter out problematic documents
        const filteredDocs = allDocs.filter(doc => this.isValidDocument(doc));

        // Store documents by ID
        filteredDocs.forEach(doc => {
            this.documents[doc.id] = this.sanitizeDocument(doc);
        });

        console.log(`Processed ${filteredDocs.length} documents (filtered from ${allDocs.length} total)`);
    }

    /**
     * Check if a document is valid for indexing
     */
    isValidDocument(doc) {
        const docId = doc.id || '';
        return !docId.toLowerCase().includes('readme') &&
               !docId.startsWith('_') &&
               doc.title &&
               doc.content;
    }

    /**
     * Sanitize document content for safe indexing
     * Supports both new schema fields and legacy fields
     * Preserves dynamic facets as-is
     */
    sanitizeDocument(doc) {
        const sanitized = {
            ...doc,
            title: this.sanitizeText(doc.title, 200),
            // Add description as separate indexed field (for improved search relevance)
            description: this.sanitizeText(doc.description, 300),
            content: this.sanitizeText(doc.content, 5000),
            summary: this.sanitizeText(doc.summary, 500),
            headings: this.sanitizeHeadings(doc.headings),
            headings_text: this.sanitizeText(doc.headings_text, 1000),
            keywords: this.sanitizeArray(doc.keywords, 300),
            tags: this.sanitizeArray(doc.tags, 200),
            // Support both topics (new) and categories (legacy)
            topics: this.sanitizeArray(doc.topics || doc.categories, 200),
            // Support both audience (new) and personas (legacy)
            audience: this.sanitizeArray(doc.audience || doc.personas, 200),
            // Content type and difficulty
            content_type: this.sanitizeText(doc.content_type, 50),
            difficulty: this.sanitizeText(doc.difficulty, 50),
            doc_type: this.sanitizeText(doc.doc_type, 50),
            section_path: this.sanitizeArray(doc.section_path, 200),
            author: this.sanitizeText(doc.author, 100)
        };

        // Preserve facets object (dynamic, user-defined keys)
        if (doc.facets && typeof doc.facets === 'object') {
            sanitized.facets = this.sanitizeFacets(doc.facets);
        }

        // Preserve legacy flat modality if present and no facets.modality
        if (doc.modality && (!doc.facets || !doc.facets.modality)) {
            sanitized.modality = this.sanitizeText(doc.modality, 50);
        }

        return sanitized;
    }

    /**
     * Sanitize facets object (dynamic keys with string or array values)
     */
    sanitizeFacets(facets) {
        const sanitized = {};
        Object.entries(facets).forEach(([key, value]) => {
            if (Array.isArray(value)) {
                sanitized[key] = value.map(v => String(v).substring(0, 100));
            } else if (value) {
                sanitized[key] = String(value).substring(0, 100);
            }
        });
        return sanitized;
    }

    /**
     * Sanitize text content with length limits
     */
    sanitizeText(text, maxLength) {
        if (!text || typeof text !== 'string') return '';
        return text.substring(0, maxLength);
    }

    /**
     * Sanitize array content
     */
    sanitizeArray(arr, maxLength) {
        if (!Array.isArray(arr)) return [];
        return arr.map(item => String(item)).join(' ').substring(0, maxLength);
    }

    /**
     * Sanitize headings array
     */
    sanitizeHeadings(headings) {
        if (!Array.isArray(headings)) return [];
        return headings.map(heading => ({
            text: this.sanitizeText(heading.text, 200),
            level: Number(heading.level) || 1
        }));
    }

    /**
     * Get all loaded documents
     */
    getDocuments() {
        return this.documents;
    }

    /**
     * Get a specific document by ID
     */
    getDocument(id) {
        return this.documents[id];
    }

    /**
     * Get document count
     */
    getDocumentCount() {
        return Object.keys(this.documents).length;
    }

    /**
     * Check if documents are loaded
     */
    isReady() {
        return this.isLoaded && Object.keys(this.documents).length > 0;
    }

    /**
     * Get documents as array for indexing
     */
    getDocumentsArray() {
        return Object.values(this.documents);
    }

    /**
     * Filter documents by criteria
     */
    filterDocuments(filterFn) {
        return this.getDocumentsArray().filter(filterFn);
    }

    /**
     * Get document statistics
     */
    getStatistics() {
        const docs = this.getDocumentsArray();
        return {
            totalDocuments: docs.length,
            documentsWithSummary: docs.filter(d => d.summary).length,
            documentsWithHeadings: docs.filter(d => d.headings && d.headings.length > 0).length,
            documentsWithTags: docs.filter(d => d.tags && d.tags.length > 0).length,
            averageContentLength: docs.reduce((sum, d) => sum + (d.content?.length || 0), 0) / docs.length
        };
    }
}

// Make DocumentLoader available globally
window.DocumentLoader = DocumentLoader;


// === SearchEngine.js ===
/**
 * SearchEngine Module
 * Handles Lunr.js integration and search logic with filtering and grouping
 */

class SearchEngine {
    constructor(utils) {
        this.utils = utils;
        this.index = null;
        this.documents = {};
        this.isInitialized = false;
        // Support both new schema (topics, audience) and legacy (categories, personas)
        this.topics = new Set();
        this.tags = new Set();
        this.documentTypes = new Set();
        this.audience = new Set();
        this.difficulties = new Set();
        // Dynamic facets - discovered from documents, not predefined
        this.facets = {}; // { facetKey: Set of values }
    }

    /**
     * Initialize the search engine with documents
     */
    async initialize(documents) {
        try {
            await this.loadLunr();
            this.documents = documents;
            this.collectMetadata();
            this.buildIndex();
            this.isInitialized = true;
        } catch (error) {
            throw error;
        }
    }

    /**
     * Collect metadata for filtering using actual frontmatter values
     * Supports both new schema (topics, audience) and legacy (categories, personas)
     * Dynamically discovers all facet keys from documents
     */
    collectMetadata() {
        // Clear existing sets
        this.topics = new Set();
        this.tags = new Set();
        this.documentTypes = new Set();
        this.audience = new Set();
        this.difficulties = new Set();
        this.facets = {}; // Reset dynamic facets

        Object.values(this.documents).forEach(doc => {
            // Collect topics (new schema) or categories (legacy)
            const topicsField = doc.topics || doc.categories;
            if (topicsField) {
                if (Array.isArray(topicsField)) {
                    topicsField.forEach(topic => this.topics.add(topic));
                } else if (typeof topicsField === 'string') {
                    topicsField.split(',').forEach(topic => this.topics.add(topic.trim()));
                }
            }

            // Collect actual frontmatter tags
            if (doc.tags) {
                if (Array.isArray(doc.tags)) {
                    doc.tags.forEach(tag => {
                        // Split space-separated tags and add individually
                        if (typeof tag === 'string' && tag.includes(' ')) {
                            tag.split(' ').forEach(individualTag => {
                                if (individualTag.trim()) {
                                    this.tags.add(individualTag.trim());
                                }
                            });
                        } else if (tag && tag.trim()) {
                            this.tags.add(tag.trim());
                        }
                    });
                } else if (typeof doc.tags === 'string') {
                    // Handle both comma-separated and space-separated tags
                    const allTags = doc.tags.includes(',')
                        ? doc.tags.split(',')
                        : doc.tags.split(' ');

                    allTags.forEach(tag => {
                        if (tag && tag.trim()) {
                            this.tags.add(tag.trim());
                        }
                    });
                }
            }

            // Use actual content_type from frontmatter (not calculated doc_type)
            if (doc.content_type) {
                this.documentTypes.add(doc.content_type);
            }

            // Collect audience (new schema) or personas (legacy)
            const audienceField = doc.audience || doc.personas;
            if (audienceField) {
                if (Array.isArray(audienceField)) {
                    audienceField.forEach(aud => this.audience.add(aud));
                } else if (typeof audienceField === 'string') {
                    this.audience.add(audienceField);
                }
            }

            if (doc.difficulty) {
                this.difficulties.add(doc.difficulty);
            }

            // Dynamically discover all facets from documents
            if (doc.facets && typeof doc.facets === 'object') {
                Object.entries(doc.facets).forEach(([facetKey, facetValue]) => {
                    // Initialize Set for this facet if not exists
                    if (!this.facets[facetKey]) {
                        this.facets[facetKey] = new Set();
                    }
                    // Add value(s) to the facet Set
                    if (Array.isArray(facetValue)) {
                        facetValue.forEach(v => this.facets[facetKey].add(v));
                    } else if (facetValue) {
                        this.facets[facetKey].add(facetValue);
                    }
                });
            }

            // Also check for flat facet fields (legacy modality, etc.)
            // These get added to facets dynamically
            if (doc.modality && !this.facets.modality) {
                this.facets.modality = new Set();
            }
            if (doc.modality) {
                this.facets.modality.add(doc.modality);
            }
        });
    }

    /**
     * Get available filter options using actual frontmatter taxonomy
     * Returns both new field names and legacy names for backwards compatibility
     * Includes dynamically discovered facets
     */
    getFilterOptions() {
        // Convert dynamic facets from Sets to sorted arrays
        const facetOptions = {};
        Object.entries(this.facets).forEach(([facetKey, facetSet]) => {
            facetOptions[facetKey] = Array.from(facetSet).sort();
        });

        return {
            // New schema names
            topics: Array.from(this.topics).sort(),
            audience: Array.from(this.audience).sort(),
            // Legacy names (aliases for backwards compatibility)
            categories: Array.from(this.topics).sort(),
            personas: Array.from(this.audience).sort(),
            // Common fields
            tags: Array.from(this.tags).sort(),
            documentTypes: Array.from(this.documentTypes).sort(),
            difficulties: Array.from(this.difficulties).sort(),
            // Dynamic facets (user-defined, discovered from documents)
            facets: facetOptions
        };
    }

    /**
     * Load Lunr.js library if not already loaded
     */
    async loadLunr() {
        if (typeof lunr === 'undefined') {
            await this.utils.loadScript('https://unpkg.com/lunr@2.3.9/lunr.min.js');
        }
    }

    /**
     * Build the Lunr search index
     * Supports both new schema (topics, audience) and legacy (categories, personas)
     *
     * Field boosting rationale:
     * - Title matches are almost always what users want (highest boost)
     * - Description (from frontmatter) is hand-crafted summary (high boost)
     * - Headings provide structural relevance (medium-high boost)
     * - Content gets lowest boost to prevent long documents from dominating
     * - Hierarchy: title > description > headings/keywords > tags > content
     */
    buildIndex() {
        const documentsArray = Object.values(this.documents);
        const self = this;

        this.index = lunr(function() {
            // Define fields with optimized boosting for documentation search patterns
            this.ref('id');

            // Primary fields - highest relevance
            this.field('title', { boost: 10 });           // Title matches most important
            this.field('description', { boost: 8 });      // Frontmatter description (hand-crafted)

            // Secondary fields - structural relevance
            this.field('keywords', { boost: 7 });         // Explicit keywords
            this.field('headings_text', { boost: 5 });    // Section headings
            this.field('headings', { boost: 5 });         // Section headings (legacy format)
            this.field('tags', { boost: 4 });             // Taxonomy tags

            // Tertiary fields - content matching
            this.field('summary', { boost: 3 });          // Summary field
            this.field('topics', { boost: 2 });           // Topic categorization
            this.field('content', { boost: 1 });          // Full content (low to prevent long docs dominating)

            // Metadata fields - filtering support
            this.field('content_type', { boost: 1 });
            this.field('audience', { boost: 1 });
            this.field('difficulty', { boost: 1 });
            this.field('modality', { boost: 1 });
            this.field('section_path', { boost: 1 });
            this.field('author', { boost: 1 });

            // Add documents to index
            documentsArray.forEach((doc) => {
                try {
                    this.add({
                        id: doc.id,
                        title: doc.title || '',
                        description: doc.description || '',  // NEW: separate indexed field
                        content: (doc.content || '').substring(0, 5000), // Limit content length
                        summary: doc.summary || '',
                        headings: self.extractHeadingsText(doc.headings),
                        headings_text: doc.headings_text || '',
                        keywords: self.arrayToString(doc.keywords),
                        tags: self.arrayToString(doc.tags),
                        // Support both topics (new) and categories (legacy)
                        topics: self.arrayToString(doc.topics || doc.categories),
                        content_type: doc.content_type || '',
                        // Support both audience (new) and personas (legacy)
                        audience: self.arrayToString(doc.audience || doc.personas),
                        difficulty: doc.difficulty || '',
                        modality: doc.modality || '',
                        section_path: self.arrayToString(doc.section_path),
                        author: doc.author || ''
                    });
                } catch (docError) {
                    // Skip documents that fail to index
                }
            }, this);
        });
    }

    /**
     * Convert array to string for indexing
     */
    arrayToString(arr) {
        if (Array.isArray(arr)) {
            return arr.join(' ');
        }
        return arr || '';
    }

    /**
     * Extract text from headings array
     */
    extractHeadingsText(headings) {
        if (!Array.isArray(headings)) return '';
        return headings.map(h => h.text || '').join(' ');
    }

    /**
     * Perform search with query and optional filters
     */
    search(query, filters = {}, maxResults = 20) {
        if (!this.isInitialized || !this.index) {
            return [];
        }

        if (!query || query.trim().length < 2) {
            return [];
        }

        try {
            // Enhanced search with multiple strategies
            const results = this.performMultiStrategySearch(query);

            // Process and enhance results
            const enhancedResults = this.enhanceResults(results, query);

            // Apply filters
            const filteredResults = this.applyFilters(enhancedResults, filters);

            // Group and rank results
            const groupedResults = this.groupResultsByDocument(filteredResults, query);

            return groupedResults.slice(0, maxResults);

        } catch (error) {
            return [];
        }
    }

    /**
     * Apply filters to search results
     * Supports both new schema (topic, audience) and legacy (category, persona) filter names
     * Handles dynamic facet filters
     */
    applyFilters(results, filters) {
        return results.filter(result => {
            // Topic filter (new) or category filter (legacy)
            const topicFilter = filters.topic || filters.category;
            if (topicFilter && topicFilter !== '') {
                const docTopics = this.getDocumentTopics(result);
                if (!docTopics.includes(topicFilter)) {
                    return false;
                }
            }

            // Tag filter
            if (filters.tag && filters.tag !== '') {
                const docTags = this.getDocumentTags(result);
                if (!docTags.includes(filters.tag)) {
                    return false;
                }
            }

            // Document type filter (using actual frontmatter content_type)
            if (filters.type && filters.type !== '') {
                if (result.content_type !== filters.type) {
                    return false;
                }
            }

            // Audience filter (new) or persona filter (legacy)
            const audienceFilter = filters.audience || filters.persona;
            if (audienceFilter && audienceFilter !== '') {
                const docAudience = this.getDocumentAudience(result);
                if (!docAudience.includes(audienceFilter)) {
                    return false;
                }
            }

            // Difficulty filter
            if (filters.difficulty && filters.difficulty !== '') {
                if (result.difficulty !== filters.difficulty) {
                    return false;
                }
            }

            // Dynamic facet filters (e.g., filters.facets = { modality: 'text-only', framework: 'pytorch' })
            if (filters.facets && typeof filters.facets === 'object') {
                for (const [facetKey, facetValue] of Object.entries(filters.facets)) {
                    if (facetValue && facetValue !== '') {
                        const docFacetValue = this.getDocumentFacet(result, facetKey);
                        if (!docFacetValue.includes(facetValue)) {
                            return false;
                        }
                    }
                }
            }

            // Legacy flat facet filters (e.g., filters.modality directly)
            // Check for any filter key that matches a known facet
            for (const facetKey of Object.keys(this.facets)) {
                if (filters[facetKey] && filters[facetKey] !== '') {
                    const docFacetValue = this.getDocumentFacet(result, facetKey);
                    if (!docFacetValue.includes(filters[facetKey])) {
                        return false;
                    }
                }
            }

            return true;
        });
    }

    /**
     * Get a specific facet value for a document
     */
    getDocumentFacet(doc, facetKey) {
        // Check nested facets object first
        if (doc.facets && doc.facets[facetKey]) {
            const value = doc.facets[facetKey];
            return Array.isArray(value) ? value : [value];
        }
        // Check flat field (legacy)
        if (doc[facetKey]) {
            const value = doc[facetKey];
            return Array.isArray(value) ? value : [value];
        }
        return [];
    }

    /**
     * Get topics for a document (supports new schema and legacy categories)
     */
    getDocumentTopics(doc) {
        const topics = [];

        // From explicit topics (new schema) or categories (legacy)
        const topicsField = doc.topics || doc.categories;
        if (topicsField) {
            if (Array.isArray(topicsField)) {
                topics.push(...topicsField);
            } else {
                topics.push(...topicsField.split(',').map(t => t.trim()));
            }
        }

        // From section path
        if (doc.section_path && Array.isArray(doc.section_path)) {
            topics.push(...doc.section_path);
        }

        // From document ID path
        if (doc.id) {
            const pathParts = doc.id.split('/').filter(part => part && part !== 'index');
            topics.push(...pathParts);
        }

        return [...new Set(topics)]; // Remove duplicates
    }

    /**
     * Get categories for a document (legacy alias for getDocumentTopics)
     */
    getDocumentCategories(doc) {
        return this.getDocumentTopics(doc);
    }

    /**
     * Get tags for a document
     */
    getDocumentTags(doc) {
        if (!doc.tags) return [];

        if (Array.isArray(doc.tags)) {
            // Handle array of tags that might contain space-separated strings
            const flatTags = [];
            doc.tags.forEach(tag => {
                if (typeof tag === 'string' && tag.includes(' ')) {
                    // Split space-separated tags
                    tag.split(' ').forEach(individualTag => {
                        if (individualTag.trim()) {
                            flatTags.push(individualTag.trim());
                        }
                    });
                } else if (tag && tag.trim()) {
                    flatTags.push(tag.trim());
                }
            });
            return flatTags;
        }

        // Handle string tags - check for both comma and space separation
        if (typeof doc.tags === 'string') {
            const allTags = [];
            const tagString = doc.tags.trim();

            if (tagString.includes(',')) {
                // Comma-separated tags
                tagString.split(',').forEach(tag => {
                    if (tag.trim()) {
                        allTags.push(tag.trim());
                    }
                });
            } else {
                // Space-separated tags
                tagString.split(' ').forEach(tag => {
                    if (tag.trim()) {
                        allTags.push(tag.trim());
                    }
                });
            }

            return allTags;
        }

        return [];
    }


    /**
     * Get audience for a document (supports new schema and legacy personas)
     */
    getDocumentAudience(doc) {
        // Support both audience (new) and personas (legacy)
        const audienceField = doc.audience || doc.personas;
        if (!audienceField) return [];

        if (Array.isArray(audienceField)) {
            return audienceField;
        }

        return [audienceField];
    }

    /**
     * Get personas for a document (legacy alias for getDocumentAudience)
     */
    getDocumentPersonas(doc) {
        return this.getDocumentAudience(doc);
    }

    /**
     * Perform search with multiple strategies
     */
    performMultiStrategySearch(query) {
        const strategies = [
            // Exact phrase search with wildcards
            `"${query}" ${query}*`,
            // Fuzzy search with wildcards
            `${query}* ${query}~2`,
            // Individual terms with boost
            query.split(/\s+/).map(term => `${term}*`).join(' '),
            // Fallback: just the query
            query
        ];

        let allResults = [];
        const seenIds = new Set();

        for (const strategy of strategies) {
            try {
                const results = this.index.search(strategy);

                // Add new results (avoid duplicates)
                results.forEach(result => {
                    if (!seenIds.has(result.ref)) {
                        seenIds.add(result.ref);
                        allResults.push({
                            ...result,
                            strategy: strategy
                        });
                    }
                });

                // If we have enough good results, stop
                if (allResults.length >= 30) break;

            } catch (strategyError) {
                console.warn(`Search strategy failed: ${strategy}`, strategyError);
            }
        }

        return allResults;
    }

    /**
     * Enhance search results with document data and apply re-ranking
     */
    enhanceResults(results, query) {
        const queryLower = query.toLowerCase().trim();
        const queryTerms = queryLower.split(/\s+/);

        return results.map(result => {
            const doc = this.documents[result.ref];
            if (!doc) {
                console.warn(`Document not found: ${result.ref}`);
                return null;
            }

            // Calculate additional relevance boost for title matches
            const titleBoost = this.calculateTitleBoost(doc, queryLower, queryTerms);
            const keywordBoost = this.calculateKeywordBoost(doc, queryTerms);
            const descriptionBoost = this.calculateDescriptionBoost(doc, queryTerms);

            // Apply boosts to base score
            const enhancedScore = result.score * (1 + titleBoost + keywordBoost + descriptionBoost);

            return {
                ...doc,
                score: enhancedScore,
                baseScore: result.score,
                titleBoost,
                keywordBoost,
                descriptionBoost,
                matchedTerms: Object.keys(result.matchData?.metadata || {}),
                matchData: result.matchData,
                strategy: result.strategy
            };
        }).filter(Boolean); // Remove null results
    }

    /**
     * Calculate boost for title matches
     * Heavily rewards exact and partial title matches
     */
    calculateTitleBoost(doc, queryLower, queryTerms) {
        if (!doc.title) return 0;

        const titleLower = doc.title.toLowerCase();
        let boost = 0;

        // Exact title match (highest boost)
        if (titleLower === queryLower) {
            boost += 10;
        }
        // Title starts with query
        else if (titleLower.startsWith(queryLower)) {
            boost += 8;
        }
        // Query is a significant part of title (e.g., "audit" in "Documentation Audit Guide")
        else if (titleLower.includes(queryLower)) {
            // Boost more if query is a larger portion of the title
            const ratio = queryLower.length / titleLower.length;
            boost += 5 * ratio + 3;
        }
        // All query terms appear in title
        else if (queryTerms.every(term => titleLower.includes(term))) {
            boost += 4;
        }
        // Some query terms appear in title
        else {
            const matchingTerms = queryTerms.filter(term => titleLower.includes(term));
            if (matchingTerms.length > 0) {
                boost += 2 * (matchingTerms.length / queryTerms.length);
            }
        }

        // Additional boost if title contains query as a distinct word
        const titleWords = titleLower.split(/[\s\-_:]+/);
        if (titleWords.some(word => word === queryLower || word.startsWith(queryLower))) {
            boost += 2;
        }

        return boost;
    }

    /**
     * Calculate boost for keyword matches
     */
    calculateKeywordBoost(doc, queryTerms) {
        if (!doc.keywords) return 0;

        const keywords = Array.isArray(doc.keywords)
            ? doc.keywords.map(k => k.toLowerCase())
            : doc.keywords.toLowerCase().split(/[\s,]+/);

        let boost = 0;

        queryTerms.forEach(term => {
            if (keywords.some(kw => kw === term || kw.startsWith(term))) {
                boost += 1.5;
            }
        });

        return boost;
    }

    /**
     * Calculate boost for description matches
     */
    calculateDescriptionBoost(doc, queryTerms) {
        if (!doc.description) return 0;

        const descLower = doc.description.toLowerCase();
        let boost = 0;

        // Check if query terms appear early in description
        queryTerms.forEach(term => {
            const pos = descLower.indexOf(term);
            if (pos !== -1) {
                // Boost more if term appears early
                boost += pos < 50 ? 1 : 0.5;
            }
        });

        return boost;
    }

    /**
     * Group results by document and find matching sections
     */
    groupResultsByDocument(results, query) {
        const grouped = new Map();

        results.forEach(result => {
            const docId = result.id;

            if (!grouped.has(docId)) {
                // Find matching sections within this document
                const matchingSections = this.findMatchingSections(result, query);

                grouped.set(docId, {
                    ...result,
                    matchingSections,
                    totalMatches: 1,
                    combinedScore: result.score
                });
            } else {
                // Document already exists, combine scores and sections
                const existing = grouped.get(docId);
                const additionalSections = this.findMatchingSections(result, query);

                existing.matchingSections = this.mergeSections(existing.matchingSections, additionalSections);
                existing.totalMatches += 1;
                existing.combinedScore = Math.max(existing.combinedScore, result.score);
            }
        });

        // Convert map to array and sort by combined score
        return Array.from(grouped.values())
            .sort((a, b) => b.combinedScore - a.combinedScore);
    }

    /**
     * Find matching sections within a document
     */
    findMatchingSections(result, query) {
        const matchingSections = [];
        const queryTerms = query.toLowerCase().split(/\s+/);

        // Check if title matches
        if (result.title) {
            const titleText = result.title.toLowerCase();
            const hasMatch = queryTerms.some(term => titleText.includes(term));

            if (hasMatch) {
                matchingSections.push({
                    type: 'title',
                    text: result.title,
                    level: 1,
                    anchor: ''
                });
            }
        }

        // Check headings for matches
        if (result.headings && Array.isArray(result.headings)) {
            result.headings.forEach(heading => {
                const headingText = heading.text?.toLowerCase() || '';
                const hasMatch = queryTerms.some(term => headingText.includes(term));

                if (hasMatch) {
                    matchingSections.push({
                        type: 'heading',
                        text: heading.text,
                        level: heading.level || 2,
                        anchor: this.generateAnchor(heading.text)
                    });
                }
            });
        }

        // If no specific sections found, add a general content match
        if (matchingSections.length === 0) {
            matchingSections.push({
                type: 'content',
                text: 'Content match',
                level: 0,
                anchor: ''
            });
        }

        return matchingSections;
    }

    /**
     * Generate anchor link similar to how Sphinx does it
     */
    generateAnchor(headingText) {
        if (!headingText) return '';

        return headingText
            .toLowerCase()
            .replace(/[^\w\s-]/g, '')  // Remove special chars
            .replace(/\s+/g, '-')      // Replace spaces with hyphens
            .trim();
    }

    /**
     * Merge sections, avoiding duplicates
     */
    mergeSections(existing, additional) {
        const merged = [...existing];

        additional.forEach(section => {
            const isDuplicate = existing.some(existingSection =>
                existingSection.text === section.text &&
                existingSection.type === section.type
            );

            if (!isDuplicate) {
                merged.push(section);
            }
        });

        return merged;
    }

    /**
     * Get search statistics
     */
    getStatistics() {
        // Count facet keys and total values
        const facetStats = {};
        Object.entries(this.facets).forEach(([key, valueSet]) => {
            facetStats[key] = valueSet.size;
        });

        return {
            documentsIndexed: Object.keys(this.documents).length,
            topicsAvailable: this.topics.size,
            tagsAvailable: this.tags.size,
            documentTypesAvailable: this.documentTypes.size,
            audienceAvailable: this.audience.size,
            difficultiesAvailable: this.difficulties.size,
            facetsDiscovered: Object.keys(this.facets).length,
            facetStats: facetStats,
            isInitialized: this.isInitialized
        };
    }

    /**
     * Check if the search engine is ready
     */
    isReady() {
        return this.isInitialized && this.index !== null;
    }
}

// Make SearchEngine available globally
window.SearchEngine = SearchEngine;


// === SearchInterface.js ===
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


// === ResultRenderer.js ===
/**
 * ResultRenderer Module
 * Handles rendering of search results in the interface
 */

class ResultRenderer {
    constructor(options, utils) {
        this.options = options;
        this.utils = utils;
    }

    /**
     * Render search results
     */
    render(results, query, container) {
        if (!container) {
            console.warn('No container provided for rendering results');
            return;
        }

        if (results.length === 0) {
            container.innerHTML = this.renderNoResults(query);
            return;
        }

        const html = results.map((result, index) => {
            const isSelected = index === 0;
            return this.renderResultItem(result, query, isSelected);
        }).join('');

        container.innerHTML = `<div class="search-results-list">${html}</div>`;

        // Bind click events
        this.bindResultEvents(container, results);
    }

    /**
     * Render a single result item
     */
    renderResultItem(result, query, isSelected = false) {
        const title = this.utils.highlightText(result.title || 'Untitled', query);
        const summary = this.utils.highlightText(result.summary || result.content?.substring(0, 200) || '', query);
        const breadcrumb = this.utils.generateBreadcrumb(result.id);

        // Render matching sections
        const sectionsHtml = this.renderMatchingSections(result, query);

        // Show multiple matches indicator
        const multipleMatchesIndicator = result.totalMatches > 1
            ? `<span class="search-result-matches-count">${result.totalMatches} matches</span>`
            : '';

        return `
            <div class="search-result-item ${isSelected ? 'selected' : ''}" tabindex="0" data-url="${this.utils.getDocumentUrl(result)}">
                <div class="search-result-content">
                    <div class="search-result-title">${title} ${multipleMatchesIndicator}</div>
                    <div class="search-result-summary">${summary}...</div>
                    ${sectionsHtml}
                    <div class="search-result-meta">
                        <span class="search-result-breadcrumb">${breadcrumb}</span>
                        ${result.tags ? `<span class="search-result-tags">${this.utils.safeArray(result.tags).slice(0, 3).map(tag => `<span class="tag">${tag}</span>`).join('')}</span>` : ''}
                    </div>
                </div>
                <div class="search-result-score">
                    <i class="fa-solid fa-arrow-right"></i>
                </div>
            </div>
        `;
    }

    /**
     * Render matching sections within a result
     */
    renderMatchingSections(result, query) {
        if (!result.matchingSections || result.matchingSections.length <= 1) {
            return '';
        }

        // Show only the first few sections to avoid overwhelming
        const sectionsToShow = result.matchingSections.slice(0, 4);
        const hasMore = result.matchingSections.length > 4;

        const sectionsHtml = sectionsToShow.map(section => {
            const icon = this.utils.getSectionIcon(section.type, section.level);
            const sectionText = this.utils.highlightText(section.text, query);
            const anchor = section.anchor ? `#${section.anchor}` : '';

            return `
                <div class="search-result-section" data-anchor="${anchor}">
                    ${icon} <span class="section-text">${sectionText}</span>
                </div>
            `;
        }).join('');

        const moreIndicator = hasMore
            ? `<div class="search-result-section-more">+${result.matchingSections.length - 4} more sections</div>`
            : '';

        return `
            <div class="search-result-sections">
                ${sectionsHtml}
                ${moreIndicator}
            </div>
        `;
    }

    /**
     * Render no results state
     */
    renderNoResults(query) {
        return `
            <div class="search-no-results">
                <i class="fa-solid fa-search-minus"></i>
                <p>No results found for "<strong>${this.utils.escapeHtml(query)}</strong>"</p>
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

    /**
     * Bind click events to result items
     */
    bindResultEvents(container, results) {
        container.querySelectorAll('.search-result-item').forEach((item, index) => {
            const result = results[index];

            // Main item click - go to document
            item.addEventListener('click', (e) => {
                // Don't trigger if clicking on a section
                if (e.target.closest('.search-result-section')) {
                    return;
                }

                const url = item.dataset.url;
                window.location.href = url;
            });

            // Section clicks - go to specific section
            item.querySelectorAll('.search-result-section').forEach(sectionEl => {
                sectionEl.addEventListener('click', (e) => {
                    e.stopPropagation();
                    const anchor = sectionEl.dataset.anchor;
                    const baseUrl = item.dataset.url;
                    window.location.href = baseUrl + anchor;
                });
            });
        });
    }

    /**
     * Get result items from container
     */
    getResultItems(container) {
        return container.querySelectorAll('.search-result-item');
    }

    /**
     * Get selected result item
     */
    getSelectedResult(container) {
        return container.querySelector('.search-result-item.selected');
    }

    /**
     * Select next result item
     */
    selectNext(container) {
        const results = this.getResultItems(container);
        const selected = this.getSelectedResult(container);

        if (results.length === 0) return;

        if (!selected) {
            results[0].classList.add('selected');
            return;
        }

        const currentIndex = Array.from(results).indexOf(selected);
        selected.classList.remove('selected');

        const nextIndex = (currentIndex + 1) % results.length;
        results[nextIndex].classList.add('selected');
        results[nextIndex].scrollIntoView({ block: 'nearest' });
    }

    /**
     * Select previous result item
     */
    selectPrevious(container) {
        const results = this.getResultItems(container);
        const selected = this.getSelectedResult(container);

        if (results.length === 0) return;

        if (!selected) {
            results[results.length - 1].classList.add('selected');
            return;
        }

        const currentIndex = Array.from(results).indexOf(selected);
        selected.classList.remove('selected');

        const prevIndex = currentIndex === 0 ? results.length - 1 : currentIndex - 1;
        results[prevIndex].classList.add('selected');
        results[prevIndex].scrollIntoView({ block: 'nearest' });
    }

    /**
     * Activate selected result
     */
    activateSelected(container) {
        const selected = this.getSelectedResult(container);
        if (selected) {
            selected.click();
        }
    }

    /**
     * Clear all selections
     */
    clearSelection(container) {
        const results = this.getResultItems(container);
        results.forEach(result => result.classList.remove('selected'));
    }

    /**
     * Render loading state
     */
    renderLoading(container) {
        if (container) {
            container.innerHTML = `
                <div class="search-loading">
                    <i class="fa-solid fa-spinner fa-spin"></i>
                    <p>Searching...</p>
                </div>
            `;
        }
    }

    /**
     * Render error state
     */
    renderError(container, message = 'Search error occurred') {
        if (container) {
            container.innerHTML = `
                <div class="search-error">
                    <i class="fa-solid fa-exclamation-triangle"></i>
                    <p>${this.utils.escapeHtml(message)}</p>
                </div>
            `;
        }
    }
}

// Make ResultRenderer available globally
window.ResultRenderer = ResultRenderer;


// === EventHandler.js ===
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


// === SearchPageManager.js ===
/**
 * Search Page Manager Module
 * Handles search functionality on the dedicated search page with filtering and grouping
 */

class SearchPageManager {
    constructor() {
        this.searchInput = null;
        this.resultsContainer = null;
        this.searchEngine = null;
        this.documents = [];
        this.currentQuery = '';
        this.allResults = [];
        this.currentFilters = {
            topic: '',
            category: '',  // Legacy alias
            tag: '',
            type: '',
            facets: {}  // Dynamic facets
        };
        this.filterOptions = {
            topics: [],
            categories: [],  // Legacy alias
            tags: [],
            documentTypes: [],
            audience: [],
            personas: [],  // Legacy alias
            difficulties: [],
            facets: {}  // Dynamic facets
        };

        this.init();
    }

    async init() {
        console.log('🔍 Initializing search page...');

        // Get page elements
        this.searchInput = document.querySelector('#enhanced-search-page-input');
        this.resultsContainer = document.querySelector('#enhanced-search-page-results');

        if (!this.searchInput || !this.resultsContainer) {
            console.error('❌ Required search page elements not found');
            return;
        }

        // Wait for enhanced search to be available
        await this.waitForEnhancedSearch();

        // Create filter interface
        this.createFilterInterface();

        // Set up event listeners
        this.setupEventListeners();

        // Handle URL search parameter
        this.handleUrlSearch();

        console.log('✅ Search page initialized');
    }

    async waitForEnhancedSearch() {
        return new Promise((resolve) => {
            const checkForSearch = () => {
                if (window.enhancedSearchInstance && window.enhancedSearchInstance.isLoaded) {
                    this.searchEngine = window.enhancedSearchInstance.getSearchEngine();
                    this.documents = window.enhancedSearchInstance.getDocuments();

                    // Get filter options
                    if (this.searchEngine && this.searchEngine.getFilterOptions) {
                        this.filterOptions = this.searchEngine.getFilterOptions();
                        console.log('✅ Filter options loaded:', this.filterOptions);
                    }

                    resolve();
                } else {
                    setTimeout(checkForSearch, 100);
                }
            };
            checkForSearch();
        });
    }

    createFilterInterface() {
        // Get the search controls container
        const searchControlsContainer = this.searchInput.parentNode;

        // Add unified styling to the container
        searchControlsContainer.className = 'search-controls-container mb-4';

        // Create filter section
        const filterSection = document.createElement('div');
        filterSection.className = 'search-filters';
        filterSection.innerHTML = this.renderFilterInterface();

        // Wrap the search input in a styled container
        const searchInputWrapper = document.createElement('div');
        searchInputWrapper.className = 'search-input-wrapper';
        searchInputWrapper.innerHTML = `
            <i class="fa-solid fa-magnifying-glass search-input-icon"></i>
        `;
        this.searchInput.parentNode.insertBefore(searchInputWrapper, this.searchInput);
        searchInputWrapper.appendChild(this.searchInput);

        // Insert filters before the search input wrapper within the same container
        searchControlsContainer.insertBefore(filterSection, searchInputWrapper);

        // Add search input wrapper class for consistent styling
        this.searchInput.className = 'search-input-field';
        this.searchInput.placeholder = 'Search documentation...';

        // Bind filter events
        this.bindFilterEvents();
    }

    renderFilterInterface() {
        // Use topics (new) or categories (legacy) with null safety
        const topics = this.filterOptions.topics || this.filterOptions.categories || [];
        const topicOptions = topics.map(topic =>
            `<option value="${this.escapeHtml(topic)}">${this.escapeHtml(this.formatCategoryName(topic))}</option>`
        ).join('');

        const tags = this.filterOptions.tags || [];
        const tagOptions = tags.map(tag =>
            `<option value="${this.escapeHtml(tag)}">${this.escapeHtml(tag)}</option>`
        ).join('');

        const types = this.filterOptions.documentTypes || [];
        const typeOptions = types.map(type =>
            `<option value="${this.escapeHtml(type)}">${this.escapeHtml(this.formatTypeName(type))}</option>`
        ).join('');

        // Use audience (new) or personas (legacy) with null safety
        const audience = this.filterOptions.audience || this.filterOptions.personas || [];
        const audienceOptions = audience.map(aud =>
            `<option value="${this.escapeHtml(aud)}">${this.escapeHtml(this.formatPersonaName(aud))}</option>`
        ).join('');

        const difficulties = this.filterOptions.difficulties || [];
        const difficultyOptions = difficulties.map(difficulty =>
            `<option value="${this.escapeHtml(difficulty)}">${this.escapeHtml(this.formatDifficultyName(difficulty))}</option>`
        ).join('');

        // Dynamic facets - render additional filter dropdowns for each facet
        const facetFilters = this.renderDynamicFacetFilters();

        // Count active filters
        const activeCount = this.getActiveFilterCount();

        return `
            <div class="filter-header">
                <div class="filter-header-left">
                    <i class="fa-solid fa-sliders filter-header-icon"></i>
                    <span class="filter-header-title">Filters</span>
                    ${activeCount > 0 ? `<span class="active-filter-count">${activeCount}</span>` : ''}
                </div>
                <button id="clear-filters" class="filter-clear-btn ${activeCount === 0 ? 'hidden' : ''}" aria-label="Clear all filters">
                    <i class="fa-solid fa-xmark"></i>
                    <span>Clear all</span>
                </button>
            </div>
            <div class="filter-grid">
                <div class="filter-group">
                    <label class="filter-label" for="topic-filter">
                        <i class="fa-solid fa-folder"></i>
                        Topic
                    </label>
                    <div class="filter-select-wrapper">
                        <select id="topic-filter" class="filter-select" aria-label="Filter by topic">
                            <option value="">All Topics</option>
                            ${topicOptions}
                        </select>
                        <i class="fa-solid fa-chevron-down filter-select-arrow"></i>
                    </div>
                </div>

                <div class="filter-group">
                    <label class="filter-label" for="tag-filter">
                        <i class="fa-solid fa-tag"></i>
                        Tag
                    </label>
                    <div class="filter-select-wrapper">
                        <select id="tag-filter" class="filter-select" aria-label="Filter by tag">
                            <option value="">All Tags</option>
                            ${tagOptions}
                        </select>
                        <i class="fa-solid fa-chevron-down filter-select-arrow"></i>
                    </div>
                </div>

                <div class="filter-group">
                    <label class="filter-label" for="type-filter">
                        <i class="fa-solid fa-file-lines"></i>
                        Type
                    </label>
                    <div class="filter-select-wrapper">
                        <select id="type-filter" class="filter-select" aria-label="Filter by content type">
                            <option value="">All Types</option>
                            ${typeOptions}
                        </select>
                        <i class="fa-solid fa-chevron-down filter-select-arrow"></i>
                    </div>
                </div>

                ${facetFilters}
            </div>
        `;
    }

    getActiveFilterCount() {
        let count = 0;
        if (this.currentFilters.topic || this.currentFilters.category) count++;
        if (this.currentFilters.tag) count++;
        if (this.currentFilters.type) count++;
        if (this.currentFilters.facets) {
            Object.values(this.currentFilters.facets).forEach(v => { if (v) count++; });
        }
        return count;
    }

    updateFilterUI() {
        const activeCount = this.getActiveFilterCount();
        const countBadge = document.querySelector('.active-filter-count');
        const clearBtn = document.getElementById('clear-filters');

        if (countBadge) {
            if (activeCount > 0) {
                countBadge.textContent = activeCount;
                countBadge.style.display = 'inline-flex';
            } else {
                countBadge.style.display = 'none';
            }
        }

        if (clearBtn) {
            clearBtn.classList.toggle('hidden', activeCount === 0);
        }

        // Update select wrappers with active state
        document.querySelectorAll('.filter-select').forEach(select => {
            const wrapper = select.closest('.filter-select-wrapper');
            if (wrapper) {
                wrapper.classList.toggle('has-value', select.value !== '');
            }
        });
    }

    renderDynamicFacetFilters() {
        const facets = this.filterOptions.facets || {};

        return Object.entries(facets).map(([facetKey, facetValues]) => {
            if (!Array.isArray(facetValues) || facetValues.length === 0) return '';

            const options = facetValues.map(value =>
                `<option value="${value}">${this.formatFacetValue(value)}</option>`
            ).join('');

            const icon = this.getFacetIcon(facetKey);

            return `
                <div class="filter-group">
                    <label class="filter-label" for="facet-${facetKey}-filter">
                        <i class="${icon}"></i>
                        ${this.formatFacetName(facetKey)}
                    </label>
                    <div class="filter-select-wrapper">
                        <select id="facet-${facetKey}-filter" class="filter-select facet-filter" data-facet-key="${facetKey}">
                            <option value="">All ${this.formatFacetName(facetKey)}</option>
                            ${options}
                        </select>
                        <i class="fa-solid fa-chevron-down filter-select-arrow"></i>
                    </div>
                </div>
            `;
        }).join('');
    }

    getFacetIcon(facetKey) {
        const iconMap = {
            'modality': 'fa-solid fa-layer-group',
            'framework': 'fa-solid fa-cube',
            'platform': 'fa-solid fa-desktop',
            'language': 'fa-solid fa-code',
            'version': 'fa-solid fa-code-branch',
            'status': 'fa-solid fa-circle-check'
        };
        return iconMap[facetKey.toLowerCase()] || 'fa-solid fa-filter';
    }

    formatFacetName(facetKey) {
        return facetKey
            .split(/[-_]/)
            .map(word => word.charAt(0).toUpperCase() + word.slice(1))
            .join(' ');
    }

    formatFacetValue(value) {
        if (typeof value !== 'string') return String(value);
        return value
            .split(/[-_]/)
            .map(word => word.charAt(0).toUpperCase() + word.slice(1))
            .join(' ');
    }

    formatCategoryName(category) {
        return category
            .split(/[-_]/)
            .map(word => word.charAt(0).toUpperCase() + word.slice(1))
            .join(' ');
    }

    formatTypeName(type) {
        return type
            .split(/[-_]/)
            .map(word => word.charAt(0).toUpperCase() + word.slice(1))
            .join(' ');
    }

    formatPersonaName(persona) {
        // Convert "data-scientist-focused" to "Data Scientist Focused"
        return persona
            .replace(/-focused$/, '') // Remove "-focused" suffix
            .split(/[-_]/)
            .map(word => word.charAt(0).toUpperCase() + word.slice(1))
            .join(' ');
    }

    formatDifficultyName(difficulty) {
        return difficulty.charAt(0).toUpperCase() + difficulty.slice(1);
    }

    formatModalityName(modality) {
        return modality
            .split(/[-_]/)
            .map(word => word.charAt(0).toUpperCase() + word.slice(1))
            .join(' ');
    }

    bindFilterEvents() {
        // Topic filter (new schema, replaces category)
        const topicFilter = document.getElementById('topic-filter');
        if (topicFilter) {
            topicFilter.addEventListener('change', (e) => {
                this.currentFilters.topic = e.target.value;
                this.currentFilters.category = e.target.value; // Legacy alias
                this.updateFilterUI();
                this.applyFiltersAndSearch();
            });
        }

        // Tag filter
        const tagFilter = document.getElementById('tag-filter');
        if (tagFilter) {
            tagFilter.addEventListener('change', (e) => {
                this.currentFilters.tag = e.target.value;
                this.updateFilterUI();
                this.applyFiltersAndSearch();
            });
        }

        // Type filter
        const typeFilter = document.getElementById('type-filter');
        if (typeFilter) {
            typeFilter.addEventListener('change', (e) => {
                this.currentFilters.type = e.target.value;
                this.updateFilterUI();
                this.applyFiltersAndSearch();
            });
        }

        // Dynamic facet filters
        document.querySelectorAll('.facet-filter').forEach(select => {
            select.addEventListener('change', (e) => {
                const facetKey = e.target.dataset.facetKey;
                if (!this.currentFilters.facets) {
                    this.currentFilters.facets = {};
                }
                this.currentFilters.facets[facetKey] = e.target.value;
                // Also set flat key for backwards compatibility
                this.currentFilters[facetKey] = e.target.value;
                this.updateFilterUI();
                this.applyFiltersAndSearch();
            });
        });

        // Clear filters
        const clearBtn = document.getElementById('clear-filters');
        if (clearBtn) {
            clearBtn.addEventListener('click', () => {
                this.clearFilters();
            });
        }
    }

    clearFilters() {
        this.currentFilters = {
            topic: '',
            category: '',  // Legacy alias
            tag: '',
            type: '',
            facets: {}
        };

        // Reset filter selects with null safety
        const topicFilter = document.getElementById('topic-filter');
        if (topicFilter) topicFilter.value = '';

        const tagFilter = document.getElementById('tag-filter');
        if (tagFilter) tagFilter.value = '';

        const typeFilter = document.getElementById('type-filter');
        if (typeFilter) typeFilter.value = '';

        // Reset dynamic facet filters
        document.querySelectorAll('.facet-filter').forEach(select => {
            select.value = '';
        });

        // Update filter UI state
        this.updateFilterUI();

        // Clear active filter display
        this.updateActiveFiltersDisplay();

        // Re-run search
        this.applyFiltersAndSearch();
    }

    handleBadgeClick(filterType, filterValue) {
        // Handle dynamic facet filters (facet-modality, facet-framework, etc.)
        if (filterType.startsWith('facet-')) {
            const facetKey = filterType.replace('facet-', '');
            if (!this.currentFilters.facets) {
                this.currentFilters.facets = {};
            }
            this.currentFilters.facets[facetKey] = filterValue;
            this.currentFilters[facetKey] = filterValue; // Flat alias

            // Update dropdown if it exists
            const dropdown = document.getElementById(`facet-${facetKey}-filter`);
            if (dropdown) {
                dropdown.value = filterValue;
            }
        } else {
            // Standard filter
            this.currentFilters[filterType] = filterValue;

            // Handle legacy aliases and update corresponding dropdowns
            if (filterType === 'topic') {
                this.currentFilters.category = filterValue;
                const topicDropdown = document.getElementById('topic-filter');
                if (topicDropdown) topicDropdown.value = filterValue;
            } else if (filterType === 'audience') {
                this.currentFilters.persona = filterValue;
                const audienceDropdown = document.getElementById('audience-filter');
                if (audienceDropdown) audienceDropdown.value = filterValue;
            } else if (filterType === 'difficulty') {
                const difficultyDropdown = document.getElementById('difficulty-filter');
                if (difficultyDropdown) difficultyDropdown.value = filterValue;
            } else if (filterType === 'tag') {
                const tagDropdown = document.getElementById('tag-filter');
                if (tagDropdown) tagDropdown.value = filterValue;
            } else if (filterType === 'type') {
                const typeDropdown = document.getElementById('type-filter');
                if (typeDropdown) typeDropdown.value = filterValue;
            } else {
                // Fallback: try to update dropdown by filter type
                const dropdown = document.getElementById(`${filterType}-filter`);
                if (dropdown) {
                    dropdown.value = filterValue;
                }
            }
        }

        // Update active filters display
        this.updateActiveFiltersDisplay();

        // Re-run search
        this.applyFiltersAndSearch();
    }

    updateActiveFiltersDisplay() {
        // Remove existing active filters display
        const existingDisplay = document.querySelector('.active-filters-display');
        if (existingDisplay) {
            existingDisplay.remove();
        }

        // Check for active dynamic facet filters (not in standard dropdowns)
        const activeMetadataFilters = [];

        // Dynamic facet filters
        if (this.currentFilters.facets) {
            Object.entries(this.currentFilters.facets).forEach(([facetKey, facetValue]) => {
                if (facetValue) {
                    activeMetadataFilters.push(`🏷️ ${this.formatFacetName(facetKey)}: ${this.formatFacetValue(facetValue)}`);
                }
            });
        }

        if (activeMetadataFilters.length > 0) {
            const filtersContainer = document.querySelector('.search-filters');
            if (filtersContainer) {
                const activeFiltersHtml = `
                    <div class="active-filters-display mb-2">
                        <small class="text-muted">Active filters: </small>
                        ${activeMetadataFilters.map(filter => `<span class="active-filter-badge">${filter}</span>`).join(' ')}
                        <button class="btn btn-outline-secondary btn-sm ms-2" onclick="window.searchPageManager.clearMetadataFilters()">
                            <i class="fa-solid fa-xmark"></i> Clear metadata filters
                        </button>
                    </div>
                `;
                filtersContainer.insertAdjacentHTML('afterend', activeFiltersHtml);
            }
        }
    }

    clearMetadataFilters() {
        this.currentFilters.facets = {};

        // Reset dynamic facet filters in UI
        document.querySelectorAll('.facet-filter').forEach(select => {
            select.value = '';
        });

        this.updateActiveFiltersDisplay();
        this.applyFiltersAndSearch();
    }

    applyFiltersAndSearch() {
        if (this.currentQuery) {
            this.handleSearch(this.currentQuery);
        }
    }

    setupEventListeners() {
        // Search input
        this.searchInput.addEventListener('input', this.debounce((e) => {
            this.handleSearch(e.target.value);
        }, 300));

        this.searchInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                this.handleSearch(e.target.value);
            }
        });

        // Badge click handlers (using event delegation)
        this.resultsContainer.addEventListener('click', (e) => {
            if (e.target.classList.contains('clickable-badge')) {
                const filterType = e.target.dataset.filterType;
                const filterValue = e.target.dataset.filterValue;
                this.handleBadgeClick(filterType, filterValue);
            }
        });

        // Make instance available globally for button callbacks
        window.searchPageManager = this;

        // Initialize keyboard navigation state
        this.focusedIndex = -1;

        // Focus input on page load
        this.searchInput.focus();
    }

    /**
     * Setup keyboard navigation for search results
     */
    setupKeyboardNavigation() {
        // Reset focused index when results change
        this.focusedIndex = -1;

        // Use a single event listener on the document (avoiding duplicates)
        if (!this.keyboardNavigationInitialized) {
            this.keyboardNavigationInitialized = true;

            document.addEventListener('keydown', (e) => {
                const results = this.resultsContainer.querySelectorAll('.search-result');
                if (results.length === 0) return;

                // Only handle when search area is focused
                if (!this.isSearchFocused()) return;

                if (e.key === 'ArrowDown') {
                    e.preventDefault();
                    this.focusedIndex = Math.min(this.focusedIndex + 1, results.length - 1);
                    this.focusResult(results, this.focusedIndex);
                } else if (e.key === 'ArrowUp') {
                    e.preventDefault();
                    this.focusedIndex = Math.max(this.focusedIndex - 1, 0);
                    this.focusResult(results, this.focusedIndex);
                } else if (e.key === 'Enter' && this.focusedIndex >= 0) {
                    e.preventDefault();
                    const link = results[this.focusedIndex].querySelector('a');
                    if (link) link.click();
                } else if (e.key === 'Escape') {
                    this.focusedIndex = -1;
                    this.clearFocus();
                    this.searchInput.focus();
                }
            });
        }
    }

    /**
     * Check if search area is focused
     */
    isSearchFocused() {
        const active = document.activeElement;
        return active === this.searchInput ||
            this.resultsContainer.contains(active) ||
            this.resultsContainer.querySelector('.focused');
    }

    /**
     * Focus a specific result by index
     */
    focusResult(results, index) {
        this.clearFocus();
        const element = results[index];
        if (element) {
            element.classList.add('focused');
            element.setAttribute('aria-selected', 'true');
            element.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }
    }

    /**
     * Clear focus from all results
     */
    clearFocus() {
        this.resultsContainer.querySelectorAll('.search-result.focused')
            .forEach(el => {
                el.classList.remove('focused');
                el.setAttribute('aria-selected', 'false');
            });
    }

    handleUrlSearch() {
        const urlParams = new URLSearchParams(window.location.search);
        const query = urlParams.get('q');
        if (query) {
            this.searchInput.value = query;
            this.handleSearch(query);
        }
    }

    handleSearch(query) {
        this.currentQuery = query.trim();

        if (!this.currentQuery) {
            this.showEmptyState();
            return;
        }

        if (this.currentQuery.length < 2) {
            this.showMinLengthMessage();
            return;
        }

        // Perform search with filters
        const results = this.searchEngine.search(this.currentQuery, this.currentFilters);
        this.allResults = results;
        this.displayResults(results);

        // Update URL without reload
        const newUrl = new URL(window.location);
        newUrl.searchParams.set('q', this.currentQuery);
        window.history.replaceState(null, '', newUrl);
    }

    displayResults(results) {
        if (results.length === 0) {
            this.showNoResults();
            return;
        }

        const resultsHtml = results.map((result, index) => this.renderResult(result, index)).join('');
        const resultBreakdown = this.getResultBreakdown(results);

        this.resultsContainer.innerHTML = `
            <div id="ai-assistant-container" class="ai-assistant-container mb-4" style="display: none;"></div>
            <div class="search-results-header mb-4">
                <h3>Search Results</h3>
                <p class="text-muted">
                    Found ${results.length} result${results.length !== 1 ? 's' : ''} for "${this.escapeHtml(this.currentQuery)}"
                    ${this.getActiveFiltersText()}
                    ${resultBreakdown ? `<span class="result-breakdown">${resultBreakdown}</span>` : ''}
                </p>
            </div>
            <div class="search-results-list" role="listbox" aria-label="Search results">
                ${resultsHtml}
            </div>
        `;

        // Setup keyboard navigation
        this.setupKeyboardNavigation();

        // Emit event for AI assistant integration
        this.emitSearchAIRequest(this.currentQuery, results);
    }

    /**
     * Get result type breakdown for display
     */
    getResultBreakdown(results) {
        const byType = {};
        results.forEach(r => {
            const type = r.content_type || 'Other';
            byType[type] = (byType[type] || 0) + 1;
        });

        const breakdown = Object.entries(byType)
            .sort((a, b) => b[1] - a[1])
            .map(([type, count]) => `${count} ${this.escapeHtml(this.formatTypeName(type))}`)
            .join(' · ');

        return breakdown;
    }

    /**
     * Render topic badges for a result
     */
    renderTopicBadges(result) {
        const topics = this.searchEngine.getDocumentTopics
            ? this.searchEngine.getDocumentTopics(result)
            : [];

        if (!topics || topics.length === 0) return '';

        const topicBadges = topics.slice(0, 3).map(topic =>
            `<span class="topic-badge clickable-badge"
                   data-filter-type="topic"
                   data-filter-value="${this.escapeHtml(topic)}"
                   title="Click to filter by ${this.escapeHtml(topic)}">
                📁 ${this.escapeHtml(topic)}
            </span>`
        ).join('');

        const moreBadge = topics.length > 3
            ? `<span class="more-topics">+${topics.length - 3}</span>`
            : '';

        return `<div class="result-topics mb-2">${topicBadges}${moreBadge}</div>`;
    }

    getActiveFiltersText() {
        const activeFilters = [];

        // Topic (new) or category (legacy)
        const topicFilter = this.currentFilters.topic || this.currentFilters.category;
        if (topicFilter) {
            activeFilters.push(`Topic: ${this.formatCategoryName(topicFilter)}`);
        }
        if (this.currentFilters.tag) {
            activeFilters.push(`Tag: ${this.currentFilters.tag}`);
        }
        if (this.currentFilters.type) {
            activeFilters.push(`Type: ${this.formatTypeName(this.currentFilters.type)}`);
        }

        // Dynamic facets
        if (this.currentFilters.facets) {
            Object.entries(this.currentFilters.facets).forEach(([facetKey, facetValue]) => {
                if (facetValue) {
                    activeFilters.push(`${this.formatFacetName(facetKey)}: ${this.formatFacetValue(facetValue)}`);
                }
            });
        }

        return activeFilters.length > 0 ? ` (filtered by ${activeFilters.join(', ')})` : '';
    }

    renderResult(result, index) {
        const title = this.highlightText(result.title, this.currentQuery);
        // Use description (frontmatter) > summary > generated snippet
        const snippetSource = result.description || result.summary || this.generateSnippet(result.content, this.currentQuery, 200);
        const summary = this.highlightText(snippetSource || '', this.currentQuery);
        const breadcrumb = this.getBreadcrumb(result.id);
        const sectionInfo = this.getSectionInfo(result.id);
        const matchingSections = this.renderMatchingSections(result, this.currentQuery);
        const resultTags = this.renderResultTags(result);
        const topicBadges = this.renderTopicBadges(result);
        const metadataBadges = this.renderMetadataBadges(result);

        // Multiple matches indicator
        const multipleMatchesIndicator = result.totalMatches > 1
            ? `<span class="multiple-matches-indicator">+${result.totalMatches - 1} more matches</span>`
            : '';

        return `
            <div class="search-result mb-4"
                 role="option"
                 aria-selected="false"
                 tabindex="-1"
                 id="result-${index}"
                 data-result-index="${index}">
                <div class="result-header d-flex align-items-start mb-2">
                    <div class="section-icon me-3">
                        <i class="${sectionInfo.icon}"></i>
                    </div>
                    <div class="result-info flex-grow-1">
                        <h4 class="result-title mb-1">
                            <a href="${this.getDocumentUrl(result)}" class="text-decoration-none">${title}</a>
                            ${multipleMatchesIndicator}
                        </h4>
                        <div class="result-breadcrumb mb-2">
                            <small class="text-muted">${breadcrumb}</small>
                        </div>
                        ${topicBadges}
                        <div class="result-meta d-flex align-items-center gap-2 mb-2 flex-wrap">
                            ${metadataBadges}
                        </div>
                        ${resultTags}
                    </div>
                </div>
                <div class="result-content">
                    <p class="result-summary mb-3">${summary}</p>
                    ${matchingSections}
                </div>
            </div>
        `;
    }

    /**
     * Generate context-aware snippet around search terms
     */
    generateSnippet(content, query, maxLength = 200) {
        if (!content) return '';

        // Find first occurrence of any search term
        const terms = query.toLowerCase().split(/\s+/).filter(t => t.length > 2);
        const lowerContent = content.toLowerCase();

        let startIndex = 0;
        for (const term of terms) {
            const idx = lowerContent.indexOf(term);
            if (idx > 0) {
                startIndex = Math.max(0, idx - 50); // Start 50 chars before match
                break;
            }
        }

        // Extract snippet around match
        let snippet = content.substring(startIndex, startIndex + maxLength);

        // Clean up word boundaries
        if (startIndex > 0) {
            const firstSpace = snippet.indexOf(' ');
            if (firstSpace > 0 && firstSpace < 20) {
                snippet = snippet.substring(firstSpace + 1);
            }
            snippet = '...' + snippet;
        }

        if (startIndex + maxLength < content.length) {
            const lastSpace = snippet.lastIndexOf(' ');
            if (lastSpace > snippet.length - 20) {
                snippet = snippet.substring(0, lastSpace);
            }
            snippet += '...';
        }

        return snippet;
    }

    renderResultTags(result) {
        const tags = this.searchEngine.getDocumentTags(result);
        if (!tags || tags.length === 0) return '';

        const tagsToShow = tags.slice(0, 6); // Show more tags since they're now on their own line
        const tagsHtml = tagsToShow.map(tag =>
            `<span class="result-tag clickable-badge" data-filter-type="tag" data-filter-value="${this.escapeHtml(tag)}" title="Click to filter by this tag">${tag}</span>`
        ).join('');

        const moreText = tags.length > 6 ? `<span class="more-tags">+${tags.length - 6} more</span>` : '';

        return `<div class="result-tags mb-2">${tagsHtml}${moreText}</div>`;
    }

    renderResultCategories(result) {
        // Use getDocumentTopics (new) which falls back to getDocumentCategories (legacy)
        const topics = this.searchEngine.getDocumentTopics
            ? this.searchEngine.getDocumentTopics(result)
            : this.searchEngine.getDocumentCategories(result);
        if (!topics || topics.length === 0) return '';

        const topicsHtml = topics.slice(0, 2).map(topic =>
            `<span class="result-category badge bg-info">${this.formatCategoryName(topic)}</span>`
        ).join('');

        return `<div class="result-categories">${topicsHtml}</div>`;
    }

    renderMetadataBadges(result) {
        const badges = [];

        // Audience badges (new) or personas (legacy) - render each as separate badge
        const audienceField = result.audience || result.personas;
        if (audienceField) {
            // Parse audience list - handle array, comma-separated string, or space-separated string with known patterns
            let audienceList = [];
            if (Array.isArray(audienceField)) {
                audienceList = audienceField;
            } else if (typeof audienceField === 'string') {
                // Check for comma separation first
                if (audienceField.includes(',')) {
                    audienceList = audienceField.split(',').map(a => a.trim()).filter(Boolean);
                } else {
                    // Try to match known audience patterns (e.g., "Technical Writer Developer" -> ["Technical Writer", "Developer"])
                    const knownAudiences = ['Technical Writer', 'Developer', 'Data Scientist', 'ML Engineer', 'DevOps', 'Administrator', 'Researcher'];
                    const matches = [];
                    let remaining = audienceField;

                    for (const known of knownAudiences) {
                        if (remaining.includes(known)) {
                            matches.push(known);
                            remaining = remaining.replace(known, '').trim();
                        }
                    }

                    audienceList = matches.length > 0 ? matches : [audienceField];
                }
            }

            audienceList.forEach(audience => {
                const formatted = this.formatPersonaName(audience);
                badges.push(`<span class="metadata-badge persona-badge" title="${this.escapeHtml(formatted)}">👤 ${this.escapeHtml(formatted)}</span>`);
            });
        }

        // Difficulty badge
        if (result.difficulty) {
            const difficultyIcon = this.getDifficultyIcon(result.difficulty);
            badges.push(`<span class="metadata-badge difficulty-badge" title="${this.formatDifficultyName(result.difficulty)}">${difficultyIcon} ${this.formatDifficultyName(result.difficulty)}</span>`);
        }

        // Dynamic facet badges
        if (result.facets && typeof result.facets === 'object') {
            Object.entries(result.facets).forEach(([facetKey, facetValue]) => {
                if (facetValue) {
                    const values = Array.isArray(facetValue) ? facetValue : [facetValue];
                    values.forEach(value => {
                        badges.push(`<span class="metadata-badge facet-badge" title="${this.formatFacetName(facetKey)}: ${this.formatFacetValue(value)}">🏷️ ${this.formatFacetValue(value)}</span>`);
                    });
                }
            });
        }

        // Legacy flat modality badge (if not in facets)
        if (result.modality && (!result.facets || !result.facets.modality)) {
            const modalityIcon = this.getModalityIcon(result.modality);
            badges.push(`<span class="metadata-badge modality-badge" title="${this.formatFacetValue(result.modality)}">${modalityIcon} ${this.formatFacetValue(result.modality)}</span>`);
        }

        return badges.join('');
    }

    getDifficultyIcon(difficulty) {
        switch (difficulty.toLowerCase()) {
            case 'beginner': return '🔰';
            case 'intermediate': return '📊';
            case 'advanced': return '🚀';
            case 'reference': return '📚';
            default: return '📖';
        }
    }

    getModalityIcon(modality) {
        switch (modality.toLowerCase()) {
            case 'text-only': return '📝';
            case 'image-only': return '🖼️';
            case 'video-only': return '🎥';
            case 'multimodal': return '🔀';
            case 'universal': return '🌐';
            default: return '📄';
        }
    }

    renderMatchingSections(result, query) {
        if (!result.matchingSections || result.matchingSections.length <= 1) {
            return '';
        }

        const sectionsToShow = result.matchingSections.slice(0, 5);
        const hasMore = result.matchingSections.length > 5;

        const sectionsHtml = sectionsToShow.map(section => {
            const sectionIcon = this.getSectionIcon(section.type, section.level);
            const sectionText = this.highlightText(section.text, query);
            const anchor = section.anchor ? `#${section.anchor}` : '';
            const sectionUrl = this.getDocumentUrl(result) + anchor;

            return `
                <a href="${sectionUrl}" class="section-link d-flex align-items-center text-decoration-none mb-1 p-2 rounded">
                    <span class="section-icon me-2">${sectionIcon}</span>
                    <span class="section-text flex-grow-1">${sectionText}</span>
                    <i class="fas fa-external-link-alt ms-2" style="font-size: 0.75rem;"></i>
                </a>
            `;
        }).join('');

        const moreIndicator = hasMore ? `
            <div class="text-muted small mt-1 ms-4">
                <i class="fas fa-ellipsis-h me-1"></i>
                +${result.matchingSections.length - 5} more sections
            </div>
        ` : '';

        return `
            <div class="matching-sections">
                <h5 class="h6 mb-2">
                    <i class="fas fa-list-ul me-1"></i>
                    Matching sections:
                </h5>
                <div class="section-links border rounded p-2">
                    ${sectionsHtml}
                    ${moreIndicator}
                </div>
            </div>
        `;
    }

    getSectionIcon(type, level) {
        switch (type) {
            case 'title':
                return '<i class="fas fa-file-lines"></i>';
            case 'heading':
                if (level <= 2) return '<i class="fas fa-heading"></i>';
                if (level <= 4) return '<i class="fas fa-heading text-muted"></i>';
                return '<i class="fas fa-heading text-muted"></i>';
            case 'content':
                return '<i class="fas fa-align-left text-muted"></i>';
            default:
                return '<i class="fas fa-circle-dot text-muted"></i>';
        }
    }

    getBreadcrumb(docId) {
        const parts = docId.split('/').filter(part => part && part !== 'index');
        return parts.length > 0 ? parts.join(' › ') : 'Home';
    }

    getSectionInfo(docId) {
        const path = docId.toLowerCase();

        if (path.includes('get-started') || path.includes('getting-started')) {
            return {
                class: 'getting-started',
                icon: 'fas fa-rocket',
                label: 'Getting Started'
            };
        } else if (path.includes('admin')) {
            return {
                class: 'admin',
                icon: 'fas fa-cog',
                label: 'Administration'
            };
        } else if (path.includes('reference') || path.includes('api')) {
            return {
                class: 'reference',
                icon: 'fas fa-book',
                label: 'Reference'
            };
        } else if (path.includes('about') || path.includes('concepts')) {
            return {
                class: 'about',
                icon: 'fas fa-info-circle',
                label: 'About'
            };
        } else if (path.includes('tutorial')) {
            return {
                class: 'tutorial',
                icon: 'fas fa-graduation-cap',
                label: 'Tutorial'
            };
        } else {
            return {
                class: 'default',
                icon: 'fas fa-file-lines',
                label: 'Documentation'
            };
        }
    }

    getDocumentUrl(result) {
        if (result.url) {
            return result.url;
        }
        return `${result.id.replace(/^\/+/, '')}.html`;
    }

    highlightText(text, query) {
        if (!query) return this.escapeHtml(text);

        const terms = query.toLowerCase().split(/\s+/).filter(term => term.length > 1);
        let highlightedText = this.escapeHtml(text);

        terms.forEach(term => {
            const regex = new RegExp(`(${this.escapeRegex(term)})`, 'gi');
            highlightedText = highlightedText.replace(regex, '<mark class="search-highlight">$1</mark>');
        });

        return highlightedText;
    }

    showEmptyState() {
        this.resultsContainer.innerHTML = `
            <div class="text-center py-4">
                <i class="fas fa-search fa-2x mb-3 text-success"></i>
                <h4>Search Documentation</h4>
                <p class="text-muted">Start typing to search across all documentation pages...</p>
                <div class="mt-3">
                    <small class="text-muted">
                        <i class="fas fa-lightbulb text-success"></i>
                        <strong>Search Tips:</strong> Use specific terms for better results • Use filters to narrow down results • Search includes titles, content, and headings
                    </small>
                </div>
            </div>
        `;
    }

    showMinLengthMessage() {
        this.resultsContainer.innerHTML = `
            <div class="text-center py-4">
                <i class="fas fa-keyboard fa-2x mb-3 text-muted"></i>
                <h4>Keep typing...</h4>
                <p class="text-muted">Enter at least 2 characters to search</p>
            </div>
        `;
    }

    showNoResults() {
        const filtersActive = this.currentFilters.topic || this.currentFilters.category ||
            this.currentFilters.tag || this.currentFilters.type ||
            (this.currentFilters.facets && Object.keys(this.currentFilters.facets).some(k => this.currentFilters.facets[k]));
        const suggestionText = filtersActive
            ? 'Try clearing some filters or using different keywords'
            : 'Try different keywords or check your spelling';

        this.resultsContainer.innerHTML = `
            <div class="no-results text-center py-4">
                <i class="fas fa-search fa-2x mb-3 text-muted"></i>
                <h4>No results found</h4>
                <p class="text-muted">No results found for "${this.escapeHtml(this.currentQuery)}"${this.getActiveFiltersText()}</p>
                <div class="mt-3">
                    <small class="text-muted">
                        ${suggestionText}
                    </small>
                </div>
                ${filtersActive ? `
                    <div class="mt-3">
                        <button onclick="document.getElementById('clear-filters').click()" class="btn btn-outline-secondary btn-sm">
                            <i class="fas fa-times"></i> Clear Filters
                        </button>
                    </div>
                ` : ''}
            </div>
        `;
    }

    // Utility methods
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

    escapeHtml(unsafe) {
        return unsafe
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    escapeRegex(string) {
        return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }

    emitSearchAIRequest(query, results) {
        // Emit event for AI assistant integration (search page)
        const aiRequestEvent = new CustomEvent('search-ai-request', {
            detail: {
                query: query,
                results: results,
                count: results.length,
                container: 'ai-assistant-container'
            }
        });
        document.dispatchEvent(aiRequestEvent);

        console.log(`🤖 Emitted search-ai-request event for query: "${query}" with ${results.length} results`);
    }
}


// === main.js ===
/**
 * Enhanced Search Main Entry Point
 * Loads search engine and page manager for enhanced search page
 * Does NOT interfere with default search behavior
 */

// Prevent multiple initializations
if (typeof window.EnhancedSearch !== 'undefined') {
} else {

// Import modules (will be loaded dynamically)
class EnhancedSearch {
    constructor(options = {}) {
        this.options = {
            placeholder: options.placeholder || 'Search documentation...',
            maxResults: options.maxResults || 20,
            minQueryLength: 2,
            highlightClass: 'search-highlight',
            ...options
        };

        this.isLoaded = false;

        // Module instances
        this.documentLoader = null;
        this.searchEngine = null;
        this.searchPageManager = null;
        this.utils = null;

        this.init();
    }

    async init() {
        try {
            // Load required modules
            // Modules bundled - no loading needed

            // Initialize core modules
            this.utils = new Utils();
            this.documentLoader = new DocumentLoader();
            this.searchEngine = new SearchEngine(this.utils);

            // Load documents and initialize search engine (always needed)
            await this.documentLoader.loadDocuments();
            await this.searchEngine.initialize(this.documentLoader.getDocuments());

            // Check if we're on the search page
            const isSearchPage = this.isSearchPage();

            if (isSearchPage) {
                this.searchPageManager = new SearchPageManager();
            }

            this.isLoaded = true;
        } catch (error) {
            this.fallbackToDefaultSearch();
        }
    }

    isSearchPage() {
        return window.location.pathname.includes('/search') ||
               window.location.pathname.includes('/search.html') ||
               window.location.pathname.endsWith('search/') ||
               document.querySelector('#enhanced-search-page-input') !== null ||
               document.querySelector('#enhanced-search-page-results') !== null;
    }

    async loadModules() {
        const moduleNames = [
            'Utils',
            'DocumentLoader',
            'SearchEngine',
            'SearchPageManager'
        ];

        // Load modules with smart path resolution
        const modulePromises = moduleNames.map(name =>
            this.loadModuleWithFallback(name)
        );

        await Promise.all(modulePromises);
    }

    async loadModuleWithFallback(moduleName) {
        const possiblePaths = this.getModulePaths(moduleName);

        for (const path of possiblePaths) {
            try {
                await this.loadModule(path);
                return;
            } catch (error) {
                // Continue to next path
            }
        }

        throw new Error(`Failed to load module ${moduleName} from any path`);
    }

    getModulePaths(moduleName) {
        const fileName = `${moduleName}.js`;

        // Calculate nesting level to determine correct _static path
        const pathParts = window.location.pathname.split('/').filter(part => part.length > 0);
        const htmlFile = pathParts[pathParts.length - 1];

        // Remove the HTML file from the count if it exists
        let nestingLevel = pathParts.length;
        if (htmlFile && htmlFile.endsWith('.html')) {
            nestingLevel--;
        }

        // Build the correct _static path based on nesting level
        const staticPrefix = nestingLevel > 0 ? '../'.repeat(nestingLevel) : './';
        const staticPath = `${staticPrefix}_static`;

        // Search assets only has modules directory
        const moduleDir = 'modules';

        // Generate paths in order of likelihood
        const paths = [];

        // 1. Most likely path based on calculated nesting
        paths.push(`${staticPath}/${moduleDir}/${fileName}`);

        // 2. Fallback static paths (for different nesting scenarios)
        paths.push(`_static/${moduleDir}/${fileName}`);
        paths.push(`./_static/${moduleDir}/${fileName}`);
        if (nestingLevel > 1) {
            paths.push(`../_static/${moduleDir}/${fileName}`);
        }

        // 3. Legacy fallback paths
        paths.push(`./modules/${fileName}`);
        paths.push(`../modules/${fileName}`);
        paths.push(`modules/${fileName}`);

        return paths;
    }

    async loadModule(src) {
        return new Promise((resolve, reject) => {
            const script = document.createElement('script');
            script.src = src;
            script.onload = resolve;
            script.onerror = () => reject(new Error(`Failed to load module: ${src}`));
            document.head.appendChild(script);
        });
    }

    // Public API methods
    search(query) {
        if (!this.searchEngine) {
            return [];
        }

        return this.searchEngine.search(query);
    }

    renderResults(results, query) {
        // Use SearchPageManager for search page rendering
        return '';
    }

    fallbackToDefaultSearch() {
        // Don't interfere with default search - just fallback
    }

    getDocuments() {
        return this.documentLoader ? this.documentLoader.getDocuments() : [];
    }

    get documents() {
        return this.getDocuments();
    }

    getSearchEngine() {
        return this.searchEngine;
    }

    getOptions() {
        return this.options;
    }
}

// Initialize the enhanced search system
window.EnhancedSearch = EnhancedSearch;

// Auto-initialize
document.addEventListener('DOMContentLoaded', function() {
    // Create the global instance
    window.enhancedSearchInstance = new EnhancedSearch({
        placeholder: 'Search NVIDIA documentation...',
        maxResults: 50
    });
});

} // End of duplicate prevention check

