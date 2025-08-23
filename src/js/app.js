/**
 * ABOUTME: Modern Cybersecurity Dashboard Application with full CVE integration
 * ABOUTME: Built with Alpine.js for reactive UI, Chart.js for analytics, and NVD API integration
 */

import { DataCache, HybridCache } from './cache.js';
import { Analytics } from './analytics.js';
import { Utils } from './utils.js';
import { initPerformanceMonitoring, CodeSplitter } from './performance.js';

/**
 * CVE API Integration Service
 */
class CVEService {
    constructor() {
        this.baseUrl = 'https://services.nvd.nist.gov/rest/json/cves/2.0/';
        this.cache = new HybridCache({ memorySize: 100, memoryTTL: 300000, diskTTL: 3600000 });
        this.rateLimiter = new RateLimiter(5, 30000); // 5 requests per 30 seconds
        this.apiKey = null; // Optional API key for higher rate limits
    }

    /**
     * Search CVEs with filters
     */
    async searchCVEs(options = {}) {
        const {
            cveId,
            keywordSearch,
            pubStartDate,
            pubEndDate,
            lastModStartDate,
            lastModEndDate,
            cvssV3Severity,
            resultsPerPage = 20,
            startIndex = 0
        } = options;

        const cacheKey = `cve_search_${JSON.stringify(options)}`;
        const cached = await this.cache.get(cacheKey);
        if (cached) return cached;

        await this.rateLimiter.waitForPermission();

        const params = new URLSearchParams();
        if (cveId) params.append('cveId', cveId);
        if (keywordSearch) params.append('keywordSearch', keywordSearch);
        if (pubStartDate) params.append('pubStartDate', pubStartDate);
        if (pubEndDate) params.append('pubEndDate', pubEndDate);
        if (lastModStartDate) params.append('lastModStartDate', lastModStartDate);
        if (lastModEndDate) params.append('lastModEndDate', lastModEndDate);
        if (cvssV3Severity) params.append('cvssV3Severity', cvssV3Severity);
        params.append('resultsPerPage', resultsPerPage);
        params.append('startIndex', startIndex);

        try {
            const headers = { 'Accept': 'application/json' };
            if (this.apiKey) headers['apiKey'] = this.apiKey;

            const response = await fetch(`${this.baseUrl}?${params}`, { headers });
            
            if (!response.ok) {
                throw new Error(`CVE API error: ${response.status} ${response.statusText}`);
            }

            const data = await response.json();
            await this.cache.set(cacheKey, data);
            return data;
        } catch (error) {
            console.error('CVE API request failed:', error);
            throw error;
        }
    }

    /**
     * Get specific CVE details
     */
    async getCVE(cveId) {
        return this.searchCVEs({ cveId });
    }

    /**
     * Get recent CVEs
     */
    async getRecentCVEs(days = 7, severity = null) {
        const endDate = new Date();
        const startDate = new Date();
        startDate.setDate(startDate.getDate() - days);

        const options = {
            pubStartDate: startDate.toISOString().split('T')[0] + 'T00:00:000',
            pubEndDate: endDate.toISOString().split('T')[0] + 'T23:59:999',
            resultsPerPage: 50
        };

        if (severity) options.cvssV3Severity = severity;

        return this.searchCVEs(options);
    }

    /**
     * Get CVE of the day (highest CVSS score published today)
     */
    async getCVEOfTheDay() {
        const today = new Date();
        const todayStr = today.toISOString().split('T')[0];
        
        const cacheKey = `cve_of_the_day_${todayStr}`;
        const cached = await this.cache.get(cacheKey);
        if (cached) return cached;

        try {
            const response = await this.searchCVEs({
                pubStartDate: todayStr + 'T00:00:000',
                pubEndDate: todayStr + 'T23:59:999',
                resultsPerPage: 20
            });

            if (response.vulnerabilities?.length > 0) {
                // Find CVE with highest CVSS score
                const cveOfTheDay = response.vulnerabilities
                    .map(v => v.cve)
                    .filter(cve => cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore)
                    .sort((a, b) => {
                        const scoreA = a.metrics.cvssMetricV31[0].cvssData.baseScore;
                        const scoreB = b.metrics.cvssMetricV31[0].cvssData.baseScore;
                        return scoreB - scoreA;
                    })[0];

                if (cveOfTheDay) {
                    await this.cache.set(cacheKey, cveOfTheDay);
                    return cveOfTheDay;
                }
            }

            // Fallback to recent high-severity CVE
            const fallback = await this.getRecentCVEs(3, 'HIGH');
            const cve = fallback.vulnerabilities?.[0]?.cve;
            if (cve) {
                await this.cache.set(cacheKey, cve);
                return cve;
            }
        } catch (error) {
            console.error('Failed to get CVE of the day:', error);
        }

        return null;
    }

    /**
     * Format CVE for display
     */
    formatCVE(cve) {
        const metrics = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV30?.[0] || cve.metrics?.cvssMetricV2?.[0];
        const cvssData = metrics?.cvssData;
        
        return {
            id: cve.id,
            description: cve.descriptions?.find(d => d.lang === 'en')?.value || 'No description available',
            publishedDate: cve.published,
            lastModified: cve.lastModified,
            cvssScore: cvssData?.baseScore || 0,
            cvssVector: cvssData?.vectorString || '',
            severity: this.getSeverityLevel(cvssData?.baseScore || 0),
            references: cve.references?.slice(0, 5) || [],
            weaknesses: cve.weaknesses?.map(w => w.description?.[0]?.value).filter(Boolean) || [],
            configurations: this.extractConfigurations(cve.configurations)
        };
    }

    getSeverityLevel(score) {
        if (score >= 9.0) return 'CRITICAL';
        if (score >= 7.0) return 'HIGH';
        if (score >= 4.0) return 'MEDIUM';
        if (score > 0) return 'LOW';
        return 'NONE';
    }

    extractConfigurations(configurations) {
        if (!configurations?.nodes) return [];
        
        const products = [];
        configurations.nodes.forEach(node => {
            node.cpeMatch?.forEach(match => {
                if (match.criteria) {
                    const parts = match.criteria.split(':');
                    if (parts.length >= 5) {
                        products.push(`${parts[3]} ${parts[4]}`);
                    }
                }
            });
        });
        
        return [...new Set(products)].slice(0, 10);
    }
}

/**
 * Rate Limiter for API calls
 */
class RateLimiter {
    constructor(maxRequests, windowMs) {
        this.maxRequests = maxRequests;
        this.windowMs = windowMs;
        this.requests = [];
    }

    async waitForPermission() {
        const now = Date.now();
        this.requests = this.requests.filter(time => now - time < this.windowMs);

        if (this.requests.length >= this.maxRequests) {
            const oldestRequest = Math.min(...this.requests);
            const waitTime = this.windowMs - (now - oldestRequest);
            
            if (waitTime > 0) {
                console.log(`Rate limit hit, waiting ${waitTime}ms`);
                await new Promise(resolve => setTimeout(resolve, waitTime));
                return this.waitForPermission();
            }
        }

        this.requests.push(now);
    }
}

/**
 * Threat Intelligence Service
 */
class ThreatIntelService {
    constructor() {
        this.cache = new HybridCache();
        this.sources = [
            {
                name: 'CISA Alerts',
                url: 'https://www.cisa.gov/news-events/cybersecurity-advisories',
                parser: 'cisa'
            },
            {
                name: 'US-CERT',
                url: 'https://www.cisa.gov/news-events/alerts',
                parser: 'uscert'
            }
        ];
    }

    async getThreatIntelligence() {
        const cacheKey = 'threat_intel';
        const cached = await this.cache.get(cacheKey);
        if (cached) return cached;

        try {
            // Mock threat intelligence data (in production, would fetch from real sources)
            const threats = [
                {
                    id: 'TI-001',
                    title: 'New Ransomware Campaign Targeting Healthcare',
                    severity: 'HIGH',
                    source: 'CISA',
                    published: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
                    description: 'Advanced persistent threat actors are using new encryption methods.',
                    indicators: ['192.168.1.100', 'malicious-domain.com', 'SHA256:abc123...'],
                    mitigations: ['Update antivirus signatures', 'Block suspicious IPs', 'Enable MFA']
                },
                {
                    id: 'TI-002', 
                    title: 'Zero-Day Exploit in Popular Web Framework',
                    severity: 'CRITICAL',
                    source: 'US-CERT',
                    published: new Date(Date.now() - 6 * 60 * 60 * 1000).toISOString(),
                    description: 'Remote code execution vulnerability affects millions of websites.',
                    indicators: ['CVE-2024-12345', 'exploit-kit.exe'],
                    mitigations: ['Apply patches immediately', 'Monitor web traffic', 'WAF rules']
                },
                {
                    id: 'TI-003',
                    title: 'Phishing Campaign Mimicking Banking Services',
                    severity: 'MEDIUM',
                    source: 'Security Vendor',
                    published: new Date(Date.now() - 12 * 60 * 60 * 1000).toISOString(),
                    description: 'Sophisticated phishing emails targeting financial institutions.',
                    indicators: ['phishing-site.net', 'fake-bank-login.com'],
                    mitigations: ['User awareness training', 'Email filtering', 'URL reputation']
                }
            ];

            await this.cache.set(cacheKey, threats);
            return threats;
        } catch (error) {
            console.error('Failed to fetch threat intelligence:', error);
            return [];
        }
    }
}

/**
 * Social Sharing Service
 */
class SocialService {
    static shareToTwitter(title, url) {
        const text = encodeURIComponent(`Check out: ${title}`);
        const shareUrl = `https://twitter.com/intent/tweet?text=${text}&url=${encodeURIComponent(url)}&hashtags=cybersecurity,infosec`;
        window.open(shareUrl, '_blank', 'width=550,height=420');
    }

    static shareToLinkedIn(title, url) {
        const shareUrl = `https://www.linkedin.com/sharing/share-offsite/?url=${encodeURIComponent(url)}`;
        window.open(shareUrl, '_blank', 'width=550,height=420');
    }

    static shareToReddit(title, url) {
        const shareUrl = `https://reddit.com/submit?title=${encodeURIComponent(title)}&url=${encodeURIComponent(url)}`;
        window.open(shareUrl, '_blank', 'width=550,height=420');
    }

    static copyToClipboard(text) {
        if (navigator.clipboard) {
            return navigator.clipboard.writeText(text);
        } else {
            // Fallback for older browsers
            const textArea = document.createElement('textarea');
            textArea.value = text;
            document.body.appendChild(textArea);
            textArea.select();
            document.execCommand('copy');
            document.body.removeChild(textArea);
            return Promise.resolve();
        }
    }
}

/**
 * Bookmark/Favorites Service
 */
class BookmarkService {
    constructor() {
        this.storageKey = 'cybersec_bookmarks';
    }

    getBookmarks() {
        return Utils.storage.get(this.storageKey, []);
    }

    addBookmark(post) {
        const bookmarks = this.getBookmarks();
        const existing = bookmarks.find(b => b.guid === post.guid);
        
        if (!existing) {
            bookmarks.unshift({
                ...post,
                bookmarkedAt: new Date().toISOString()
            });
            Utils.storage.set(this.storageKey, bookmarks);
            return true;
        }
        return false;
    }

    removeBookmark(guid) {
        const bookmarks = this.getBookmarks();
        const filtered = bookmarks.filter(b => b.guid !== guid);
        Utils.storage.set(this.storageKey, filtered);
        return bookmarks.length !== filtered.length;
    }

    isBookmarked(guid) {
        const bookmarks = this.getBookmarks();
        return bookmarks.some(b => b.guid === guid);
    }

    clearBookmarks() {
        Utils.storage.set(this.storageKey, []);
    }
}

/**
 * Data Export Service
 */
class ExportService {
    static exportToCSV(data, filename = 'cybersec_data.csv') {
        const headers = ['Title', 'Category', 'Published', 'Author', 'CVEs', 'Link'];
        const rows = data.map(post => [
            `"${post.title}"`,
            post.sourceCategory || '',
            post.publishedTime,
            post.author || '',
            (post.cveIds || []).join(';'),
            post.link
        ]);
        
        const csv = [headers.join(','), ...rows.map(row => row.join(','))].join('\n');
        this.downloadFile(csv, filename, 'text/csv');
    }

    static exportToJSON(data, filename = 'cybersec_data.json') {
        const json = JSON.stringify(data, null, 2);
        this.downloadFile(json, filename, 'application/json');
    }

    static downloadFile(content, filename, mimeType) {
        const blob = new Blob([content], { type: mimeType });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
    }
}

// Global dashboard application
function dashboardApp() {
    return {
        // Data state
        allPosts: [],
        filteredPosts: [],
        paginatedPosts: [],
        categories: [],
        trendingTopics: [],
        recentCVEs: [],
        stats: {
            totalPosts: 0,
            newPosts: 0,
            todayPosts: 0,
            successRate: 0
        },

        // UI state
        isLoading: true,
        darkMode: false,
        showAnalytics: false,
        showSettings: false,
        showScrollTop: false,
        viewMode: 'grid',

        // Filter state
        searchQuery: '',
        selectedCategory: '',
        timeFilter: '',
        priorityFilter: '',
        searchTimeout: null,

        // Pagination
        currentPage: 1,
        postsPerPage: 12,

        // Settings
        autoRefresh: true,
        lastUpdated: 'Loading...',

        // Charts
        categoryChart: null,
        timelineChart: null,

        // Services
        cveService: new CVEService(),
        threatIntelService: new ThreatIntelService(),
        bookmarkService: new BookmarkService(),

        // Additional UI state
        showCVEModal: false,
        currentCVE: null,
        showBookmarks: false,
        showExportModal: false,
        threatIntel: [],
        cveOfTheDay: null,
        newsTicker: [],
        keyboardNavIndex: -1,
        notifications: [],

        // Export options
        exportFormat: 'json',
        exportData: 'filtered',

        // Color palette for categories
        categoryColors: {
            'Core Security': '#FF6B6B',
            'Bug Bounty': '#4ECDC4',
            'Penetration Testing': '#45B7D1',
            'Web Security': '#96CEB4',
            'API & Mobile': '#FFEAA7',
            'Cloud Security': '#DDA0DD',
            'Tools & OSINT': '#74B9FF',
            'Malware & Threats': '#FD79A8',
            'Forensics & IR': '#FDCB6E',
            'Network Security': '#00B894',
            'Vuln Research': '#6C5CE7',
            'Blue Team & SOC': '#00CEC9',
            'Crypto & Privacy': '#E17055'
        },

        async init() {
            // Start performance monitoring
            const perfMonitor = initPerformanceMonitoring();
            Utils.performance.mark('app-init-start');
            
            console.log('🚀 Initializing Cybersecurity Dashboard...');
            
            // Initialize theme
            this.initTheme();
            
            // Initialize scroll tracking
            this.initScrollTracking();
            
            // Initialize keyboard navigation
            this.initKeyboardNavigation();
            
            // Load data with performance tracking
            await this.loadData();
            
            // Load threat intelligence and CVE data
            await this.loadThreatIntelligence();
            await this.loadCVEOfTheDay();
            
            // Initialize news ticker
            this.initNewsTicker();
            
            Utils.performance.mark('app-init-end');
            const initTime = Utils.performance.measure('app-init', 'app-init-start', 'app-init-end');
            console.log(`⚡ App initialized in ${initTime.toFixed(2)}ms`);
            
            // Log performance report
            setTimeout(() => {
                const report = perfMonitor.getPerformanceReport();
                console.log('📊 Performance Report:', report);
            }, 1000);
            
            // Setup auto-refresh
            this.setupAutoRefresh();
            
            // Initialize analytics
            this.initAnalytics();
            
            // Show welcome notification
            this.showNotification('Dashboard loaded successfully!', 'success');
            
            console.log('✅ Dashboard initialized successfully');
        },

        initTheme() {
            const savedTheme = localStorage.getItem('theme') || 'light';
            this.setTheme(savedTheme);
        },

        initScrollTracking() {
            window.addEventListener('scroll', Utils.throttle(() => {
                this.showScrollTop = window.pageYOffset > 300;
            }, 100));
        },

        initKeyboardNavigation() {
            document.addEventListener('keydown', (e) => {
                // Global keyboard shortcuts
                if (e.ctrlKey || e.metaKey) {
                    switch (e.key) {
                        case 'k':
                            e.preventDefault();
                            document.querySelector('[data-search-input]')?.focus();
                            break;
                        case 'b':
                            e.preventDefault();
                            this.showBookmarks = !this.showBookmarks;
                            break;
                        case 'd':
                            e.preventDefault();
                            this.toggleTheme();
                            break;
                        case 'e':
                            e.preventDefault();
                            this.showExportModal = true;
                            break;
                    }
                }
                
                // Escape key handling
                if (e.key === 'Escape') {
                    this.showCVEModal = false;
                    this.showSettings = false;
                    this.showBookmarks = false;
                    this.showExportModal = false;
                }
                
                // Arrow navigation for posts
                if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
                    e.preventDefault();
                    this.navigatePosts(e.key === 'ArrowDown' ? 1 : -1);
                }
                
                // Enter to open highlighted post
                if (e.key === 'Enter' && this.keyboardNavIndex >= 0) {
                    const posts = document.querySelectorAll('[data-post-link]');
                    if (posts[this.keyboardNavIndex]) {
                        posts[this.keyboardNavIndex].click();
                    }
                }
            });
        },
        
        navigatePosts(direction) {
            const posts = document.querySelectorAll('[data-post-link]');
            if (posts.length === 0) return;
            
            // Remove previous highlight
            posts.forEach(post => post.classList.remove('keyboard-highlight'));
            
            // Update index
            this.keyboardNavIndex += direction;
            
            // Wrap around
            if (this.keyboardNavIndex >= posts.length) this.keyboardNavIndex = 0;
            if (this.keyboardNavIndex < 0) this.keyboardNavIndex = posts.length - 1;
            
            // Highlight current post
            const currentPost = posts[this.keyboardNavIndex];
            currentPost.classList.add('keyboard-highlight');
            currentPost.scrollIntoView({ behavior: 'smooth', block: 'center' });
        },

        async loadThreatIntelligence() {
            try {
                this.threatIntel = await this.threatIntelService.getThreatIntelligence();
            } catch (error) {
                console.error('Failed to load threat intelligence:', error);
                this.showNotification('Failed to load threat intelligence', 'error');
            }
        },

        async loadCVEOfTheDay() {
            try {
                this.cveOfTheDay = await this.cveService.getCVEOfTheDay();
            } catch (error) {
                console.error('Failed to load CVE of the day:', error);
            }
        },

        initNewsTicker() {
            // Combine threat intel and recent posts for news ticker
            this.newsTicker = [
                ...this.threatIntel.map(threat => ({
                    type: 'threat',
                    text: `🚨 ${threat.title}`,
                    severity: threat.severity,
                    timestamp: threat.published
                })),
                ...this.allPosts.filter(p => p.isNew).slice(0, 5).map(post => ({
                    type: 'post',
                    text: `📰 ${post.title}`,
                    severity: 'INFO',
                    timestamp: post.publishedTime
                }))
            ].sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
            
            // Start ticker animation
            this.startNewsTicker();
        },

        startNewsTicker() {
            if (this.newsTicker.length === 0) return;
            
            let currentIndex = 0;
            const tickerElement = document.querySelector('[data-news-ticker]');
            
            if (!tickerElement) return;
            
            const updateTicker = () => {
                if (this.newsTicker.length > 0) {
                    const item = this.newsTicker[currentIndex % this.newsTicker.length];
                    tickerElement.innerHTML = `
                        <span class="ticker-item ${item.severity.toLowerCase()}">
                            ${item.text}
                        </span>
                    `;
                    currentIndex++;
                }
            };
            
            updateTicker();
            setInterval(updateTicker, 5000); // Change every 5 seconds
        },

        async loadData() {
            try {
                this.isLoading = true;
                
                // Try to load from cache first
                const cache = new DataCache();
                let data = await cache.get('dashboard-data');
                
                if (!data || cache.isExpired('dashboard-data', 30 * 60 * 1000)) { // 30 minutes
                    console.log('📡 Loading fresh data...');
                    data = await this.fetchFreshData();
                    await cache.set('dashboard-data', data);
                } else {
                    console.log('💾 Loading from cache...');
                }
                
                await this.processData(data);
                this.lastUpdated = new Date().toLocaleTimeString();
                
            } catch (error) {
                console.error('❌ Error loading data:', error);
                await this.loadFallbackData();
            } finally {
                this.isLoading = false;
            }
        },

        async fetchFreshData() {
            const endpoints = [
                './data/posts.json',
                './data/summary.json'
            ];
            
            const responses = await Promise.allSettled(
                endpoints.map(url => fetch(url).then(r => r.json()))
            );
            
            const [postsResult, summaryResult] = responses;
            
            if (postsResult.status === 'fulfilled' && summaryResult.status === 'fulfilled') {
                return {
                    posts: postsResult.value,
                    summary: summaryResult.value
                };
            }
            
            // Fallback to posts only
            if (postsResult.status === 'fulfilled') {
                return {
                    posts: postsResult.value,
                    summary: this.generateSummaryFromPosts(postsResult.value)
                };
            }
            
            throw new Error('Failed to fetch data');
        },

        async loadFallbackData() {
            console.log('🔄 Loading fallback data...');
            
            // Generate mock data for demonstration
            const mockData = this.generateMockData();
            await this.processData(mockData);
            this.lastUpdated = 'Demo Data';
        },

        generateMockData() {
            const categories = Object.keys(this.categoryColors);
            const posts = [];
            
            for (let i = 0; i < 50; i++) {
                const category = categories[Math.floor(Math.random() * categories.length)];
                const publishedTime = new Date(Date.now() - Math.random() * 7 * 24 * 60 * 60 * 1000).toISOString();
                const ageHours = (Date.now() - new Date(publishedTime)) / (1000 * 60 * 60);
                
                posts.push({
                    guid: `mock-${i}`,
                    title: `Mock Cybersecurity Post ${i + 1}: ${this.generateMockTitle()}`,
                    link: '#',
                    description: this.generateMockDescription(),
                    publishedTime,
                    author: `Author ${Math.floor(Math.random() * 10) + 1}`,
                    categories: [this.generateMockCategory(), this.generateMockCategory()],
                    sourceCategory: category,
                    priority: Math.floor(Math.random() * 3) + 1,
                    ageHours,
                    isNew: ageHours <= 24,
                    isToday: ageHours <= 24,
                    isThisWeek: ageHours <= 168,
                    cveIds: Math.random() > 0.7 ? [`CVE-2024-${Math.floor(Math.random() * 9999)}`] : []
                });
            }
            
            return {
                posts,
                summary: this.generateSummaryFromPosts(posts)
            };
        },

        generateMockTitle() {
            const titles = [
                'Critical XSS Vulnerability Found in Popular Framework',
                'New SQL Injection Bypass Technique Discovered',
                'Advanced Persistent Threat Analysis',
                'Zero-Day Exploit in Enterprise Software',
                'Bug Bounty Writeup: From IDOR to Account Takeover',
                'Malware Analysis: Latest Ransomware Campaign',
                'Penetration Testing Methodology Update',
                'Cloud Security Misconfiguration Leads to Data Breach'
            ];
            return titles[Math.floor(Math.random() * titles.length)];
        },

        generateMockDescription() {
            const descriptions = [
                'This post details a comprehensive analysis of a newly discovered vulnerability and its potential impact on enterprise security.',
                'A detailed walkthrough of exploitation techniques and mitigation strategies for this critical security flaw.',
                'In-depth research into advanced attack vectors and defensive countermeasures in modern cybersecurity.',
                'Technical analysis of the vulnerability discovery process and responsible disclosure timeline.'
            ];
            return descriptions[Math.floor(Math.random() * descriptions.length)];
        },

        generateMockCategory() {
            const cats = ['XSS', 'SQLi', 'RCE', 'IDOR', 'SSRF', 'LFI', 'API Security', 'Mobile Security'];
            return cats[Math.floor(Math.random() * cats.length)];
        },

        generateSummaryFromPosts(posts) {
            const now = new Date();
            const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
            const weekAgo = new Date(today.getTime() - 7 * 24 * 60 * 60 * 1000);
            
            return {
                totalPosts: posts.length,
                newPosts: posts.filter(p => p.isNew).length,
                todayPosts: posts.filter(p => p.isToday).length,
                thisWeekPosts: posts.filter(p => p.isThisWeek).length,
                categories: this.generateCategoryStats(posts),
                trendingTopics: this.generateTrendingTopics(posts),
                recentCVEs: this.extractRecentCVEs(posts),
                stats: {
                    totalFeeds: 50,
                    successfulFeeds: 45,
                    successRate: 90
                }
            };
        },

        async processData(data) {
            const { posts, summary } = data;
            
            // Store data
            this.allPosts = posts.sort((a, b) => {
                // Sort by priority, then by new posts, then by date
                if (a.priority !== b.priority) return a.priority - b.priority;
                if (a.isNew !== b.isNew) return b.isNew - a.isNew;
                return new Date(b.publishedTime) - new Date(a.publishedTime);
            });
            
            // Process summary data
            this.categories = summary.categories || this.generateCategoryStats(posts);
            this.trendingTopics = summary.trendingTopics || this.generateTrendingTopics(posts);
            this.recentCVEs = summary.recentCVEs || this.extractRecentCVEs(posts);
            
            // Update stats
            this.stats = {
                totalPosts: summary.totalPosts || posts.length,
                newPosts: summary.newPosts || posts.filter(p => p.isNew).length,
                todayPosts: summary.todayPosts || posts.filter(p => p.isToday).length,
                successRate: summary.stats?.successRate || 90
            };
            
            // Apply initial filters
            this.filterPosts();
            
            // Initialize charts after DOM is ready
            this.$nextTick(() => {
                if (this.showAnalytics) {
                    this.initCharts();
                }
            });
        },

        generateCategoryStats(posts) {
            const stats = {};
            
            posts.forEach(post => {
                const category = post.sourceCategory;
                if (!stats[category]) {
                    stats[category] = { name: category, total: 0, new: 0, today: 0 };
                }
                
                stats[category].total++;
                if (post.isNew) stats[category].new++;
                if (post.isToday) stats[category].today++;
            });
            
            return Object.values(stats).sort((a, b) => b.total - a.total);
        },

        generateTrendingTopics(posts) {
            const topics = {};
            
            posts.forEach(post => {
                post.categories?.forEach(category => {
                    const key = category.toLowerCase();
                    topics[key] = (topics[key] || 0) + 1;
                });
            });
            
            return Object.entries(topics)
                .map(([name, count]) => ({ name, count }))
                .sort((a, b) => b.count - a.count)
                .slice(0, 20);
        },

        extractRecentCVEs(posts) {
            const cves = new Set();
            
            posts
                .filter(post => post.isThisWeek)
                .forEach(post => {
                    post.cveIds?.forEach(cve => cves.add(cve));
                });
            
            return Array.from(cves).sort();
        },

        filterPosts() {
            let filtered = [...this.allPosts];
            
            // Search filter
            if (this.searchQuery.trim()) {
                const query = this.searchQuery.toLowerCase();
                filtered = filtered.filter(post => 
                    post.title.toLowerCase().includes(query) ||
                    post.description.toLowerCase().includes(query) ||
                    post.categories?.some(cat => cat.toLowerCase().includes(query)) ||
                    post.cveIds?.some(cve => cve.toLowerCase().includes(query))
                );
            }
            
            // Category filter
            if (this.selectedCategory) {
                filtered = filtered.filter(post => 
                    post.sourceCategory === this.selectedCategory
                );
            }
            
            // Time filter
            if (this.timeFilter) {
                switch (this.timeFilter) {
                    case 'today':
                        filtered = filtered.filter(post => post.isToday);
                        break;
                    case 'week':
                        filtered = filtered.filter(post => post.isThisWeek);
                        break;
                    case 'new':
                        filtered = filtered.filter(post => post.isNew);
                        break;
                }
            }
            
            // Priority filter
            if (this.priorityFilter) {
                const priorityMap = { high: [1, 2], medium: [3, 4], low: [5, 6, 7, 8] };
                const priorities = priorityMap[this.priorityFilter] || [];
                filtered = filtered.filter(post => priorities.includes(post.priority));
            }
            
            this.filteredPosts = filtered;
            this.currentPage = 1;
            this.updatePagination();
        },

        updatePagination() {
            const start = (this.currentPage - 1) * this.postsPerPage;
            const end = start + parseInt(this.postsPerPage);
            this.paginatedPosts = this.filteredPosts.slice(0, end);
        },

        debounceSearch() {
            clearTimeout(this.searchTimeout);
            this.searchTimeout = setTimeout(() => {
                this.filterPosts();
            }, 300);
        },

        loadMore() {
            this.currentPage++;
            this.updatePagination();
        },

        hasMorePosts() {
            return this.paginatedPosts.length < this.filteredPosts.length;
        },

        // Filter management
        hasActiveFilters() {
            return !!(this.searchQuery || this.selectedCategory || this.timeFilter || this.priorityFilter);
        },

        getActiveFilters() {
            const filters = [];
            
            if (this.searchQuery) {
                filters.push({ type: 'search', label: `Search: "${this.searchQuery}"` });
            }
            if (this.selectedCategory) {
                filters.push({ type: 'category', label: `Category: ${this.selectedCategory}` });
            }
            if (this.timeFilter) {
                const timeLabels = { today: 'Today', week: 'This Week', new: 'New Posts' };
                filters.push({ type: 'time', label: `Time: ${timeLabels[this.timeFilter]}` });
            }
            if (this.priorityFilter) {
                const priorityLabels = { high: 'High Priority', medium: 'Medium Priority', low: 'Low Priority' };
                filters.push({ type: 'priority', label: `Priority: ${priorityLabels[this.priorityFilter]}` });
            }
            
            return filters;
        },

        clearFilter(type) {
            switch (type) {
                case 'search':
                    this.searchQuery = '';
                    break;
                case 'category':
                    this.selectedCategory = '';
                    break;
                case 'time':
                    this.timeFilter = '';
                    break;
                case 'priority':
                    this.priorityFilter = '';
                    break;
            }
            this.filterPosts();
        },

        clearAllFilters() {
            this.searchQuery = '';
            this.selectedCategory = '';
            this.timeFilter = '';
            this.priorityFilter = '';
            this.filterPosts();
        },

        // CVE Management
        async searchCVE(cveId) {
            if (!cveId.trim()) return;
            
            try {
                this.isLoading = true;
                const response = await this.cveService.getCVE(cveId.trim());
                
                if (response.vulnerabilities?.length > 0) {
                    this.currentCVE = this.cveService.formatCVE(response.vulnerabilities[0].cve);
                    this.showCVEModal = true;
                } else {
                    this.showNotification(`CVE ${cveId} not found`, 'warning');
                }
            } catch (error) {
                console.error('CVE search failed:', error);
                this.showNotification('CVE search failed', 'error');
            } finally {
                this.isLoading = false;
            }
        },

        async showCVEDetails(cveId) {
            await this.searchCVE(cveId);
        },

        // Bookmark Management
        toggleBookmark(post) {
            const wasBookmarked = this.bookmarkService.isBookmarked(post.guid);
            
            if (wasBookmarked) {
                this.bookmarkService.removeBookmark(post.guid);
                this.showNotification('Bookmark removed', 'info');
            } else {
                this.bookmarkService.addBookmark(post);
                this.showNotification('Post bookmarked', 'success');
            }
        },

        isBookmarked(guid) {
            return this.bookmarkService.isBookmarked(guid);
        },

        getBookmarks() {
            return this.bookmarkService.getBookmarks();
        },

        clearAllBookmarks() {
            this.bookmarkService.clearBookmarks();
            this.showNotification('All bookmarks cleared', 'info');
        },

        // Social Sharing
        sharePost(post, platform) {
            const url = post.link;
            const title = post.title;
            
            switch (platform) {
                case 'twitter':
                    SocialService.shareToTwitter(title, url);
                    break;
                case 'linkedin':
                    SocialService.shareToLinkedIn(title, url);
                    break;
                case 'reddit':
                    SocialService.shareToReddit(title, url);
                    break;
                case 'copy':
                    SocialService.copyToClipboard(url)
                        .then(() => this.showNotification('Link copied to clipboard', 'success'))
                        .catch(() => this.showNotification('Failed to copy link', 'error'));
                    break;
            }
        },

        // Data Export
        exportData() {
            const data = this.exportData === 'all' ? this.allPosts : this.filteredPosts;
            const timestamp = new Date().toISOString().split('T')[0];
            const filename = `cybersec_posts_${timestamp}`;
            
            if (this.exportFormat === 'csv') {
                ExportService.exportToCSV(data, `${filename}.csv`);
            } else {
                ExportService.exportToJSON(data, `${filename}.json`);
            }
            
            this.showExportModal = false;
            this.showNotification(`Data exported as ${this.exportFormat.toUpperCase()}`, 'success');
        },

        // Notification System
        showNotification(message, type = 'info', duration = 3000) {
            const notification = {
                id: Utils.generateId('notification'),
                message,
                type,
                timestamp: Date.now()
            };
            
            this.notifications.unshift(notification);
            
            // Auto-remove after duration
            setTimeout(() => {
                this.removeNotification(notification.id);
            }, duration);
            
            // Limit to 5 notifications
            if (this.notifications.length > 5) {
                this.notifications = this.notifications.slice(0, 5);
            }
        },

        removeNotification(id) {
            this.notifications = this.notifications.filter(n => n.id !== id);
        },

        // Real-time Data Refresh
        async refreshData() {
            try {
                this.isLoading = true;
                await this.loadData();
                await this.loadThreatIntelligence();
                this.showNotification('Data refreshed successfully', 'success');
            } catch (error) {
                this.showNotification('Failed to refresh data', 'error');
            } finally {
                this.isLoading = false;
            }
        },

        // Enhanced Error Handling
        handleError(error, context = '') {
            Utils.error.log(error, context);
            this.showNotification(`Error: ${error.message}`, 'error');
        },

        // Theme management
        toggleTheme() {
            this.setTheme(this.darkMode ? 'light' : 'dark');
        },

        setTheme(theme) {
            this.darkMode = theme === 'dark';
            document.documentElement.setAttribute('data-theme', theme);
            localStorage.setItem('theme', theme);
            
            // Update charts if they exist
            if (this.categoryChart || this.timelineChart) {
                this.$nextTick(() => this.initCharts());
            }
        },

        // Auto-refresh
        setupAutoRefresh() {
            if (this.autoRefresh) {
                setInterval(() => {
                    this.loadData();
                }, 2 * 60 * 60 * 1000); // 2 hours
            }
        },

        toggleAutoRefresh() {
            localStorage.setItem('autoRefresh', this.autoRefresh);
            if (this.autoRefresh) {
                this.setupAutoRefresh();
            }
        },

        // Utility functions
        formatTimeAgo(dateString) {
            return Utils.formatTimeAgo(dateString);
        },

        highlightSearchTerm(text) {
            if (!this.searchQuery.trim() || !text) return text;
            
            const regex = new RegExp(`(${this.searchQuery})`, 'gi');
            return DOMPurify.sanitize(
                text.replace(regex, '<span class="search-highlight">$1</span>')
            );
        },

        getPriorityClass(priority) {
            if (priority <= 2) return 'priority-high';
            if (priority <= 4) return 'priority-medium';
            return 'priority-low';
        },

        getCategoryColor(category) {
            return this.categoryColors[category] || '#6B7280';
        },

        animateCard(element, index) {
            element.style.animationDelay = `${index * 0.1}s`;
            element.classList.add('animate-fade-in-up');
        },

        scrollToTop() {
            window.scrollTo({ top: 0, behavior: 'smooth' });
        },

        // Enhanced UI helpers
        getPostCardClasses(post) {
            let classes = 'glass rounded-lg overflow-hidden hover-lift';
            classes += ` ${this.getPriorityClass(post.priority)}`;
            if (this.isBookmarked(post.guid)) classes += ' bookmarked';
            return classes;
        },

        getSeverityColor(severity) {
            const colors = {
                'CRITICAL': '#dc2626',
                'HIGH': '#ea580c', 
                'MEDIUM': '#d97706',
                'LOW': '#65a30d',
                'NONE': '#6b7280'
            };
            return colors[severity] || colors.NONE;
        },

        formatCVSSScore(score) {
            if (!score) return 'N/A';
            return `${score.toFixed(1)}`;
        },

        // Accessibility helpers
        announceToScreenReader(message) {
            const announcement = document.createElement('div');
            announcement.setAttribute('aria-live', 'polite');
            announcement.setAttribute('aria-atomic', 'true');
            announcement.className = 'sr-only';
            announcement.textContent = message;
            
            document.body.appendChild(announcement);
            setTimeout(() => {
                document.body.removeChild(announcement);
            }, 1000);
        },

        // Analytics
        initAnalytics() {
            this.$watch('showAnalytics', (show) => {
                if (show) {
                    this.$nextTick(() => this.initCharts());
                }
            });
        },

        initCharts() {
            this.initCategoryChart();
            this.initTimelineChart();
        },

        initCategoryChart() {
            const ctx = document.getElementById('categoryChart');
            if (!ctx) return;
            
            if (this.categoryChart) {
                this.categoryChart.destroy();
            }
            
            const data = this.categories.slice(0, 8); // Top 8 categories
            
            this.categoryChart = new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: data.map(c => c.name),
                    datasets: [{
                        data: data.map(c => c.total),
                        backgroundColor: data.map(c => this.getCategoryColor(c.name)),
                        borderWidth: 2,
                        borderColor: this.darkMode ? '#374151' : '#ffffff'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: {
                                color: this.darkMode ? '#e5e7eb' : '#374151',
                                padding: 15,
                                usePointStyle: true
                            }
                        }
                    }
                }
            });
        },

        initTimelineChart() {
            const ctx = document.getElementById('timelineChart');
            if (!ctx) return;
            
            if (this.timelineChart) {
                this.timelineChart.destroy();
            }
            
            // Generate timeline data for the past 7 days
            const days = [];
            const counts = [];
            
            for (let i = 6; i >= 0; i--) {
                const date = new Date();
                date.setDate(date.getDate() - i);
                const dayStr = date.toLocaleDateString('en-US', { weekday: 'short' });
                
                const dayStart = new Date(date.getFullYear(), date.getMonth(), date.getDate());
                const dayEnd = new Date(dayStart.getTime() + 24 * 60 * 60 * 1000);
                
                const count = this.allPosts.filter(post => {
                    const postDate = new Date(post.publishedTime);
                    return postDate >= dayStart && postDate < dayEnd;
                }).length;
                
                days.push(dayStr);
                counts.push(count);
            }
            
            this.timelineChart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: days,
                    datasets: [{
                        label: 'Posts',
                        data: counts,
                        borderColor: '#667eea',
                        backgroundColor: 'rgba(102, 126, 234, 0.1)',
                        borderWidth: 2,
                        fill: true,
                        tension: 0.4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            display: false
                        }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            ticks: {
                                color: this.darkMode ? '#e5e7eb' : '#374151'
                            },
                            grid: {
                                color: this.darkMode ? '#374151' : '#e5e7eb'
                            }
                        },
                        x: {
                            ticks: {
                                color: this.darkMode ? '#e5e7eb' : '#374151'
                            },
                            grid: {
                                color: this.darkMode ? '#374151' : '#e5e7eb'
                            }
                        }
                    },
                    onHover: (event, elements) => {
                        if (elements.length > 0) {
                            const index = elements[0].index;
                            const day = days[index];
                            const count = counts[index];
                            this.announceToScreenReader(`${day}: ${count} posts`);
                        }
                    }
                }
            });
        }
    };
}

// Make dashboard app globally available
window.dashboardApp = dashboardApp;

// Export for module use
export { dashboardApp, CVEService, ThreatIntelService, SocialService, BookmarkService, ExportService };