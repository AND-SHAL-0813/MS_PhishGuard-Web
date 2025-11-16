// MS_PhishGuard - AI-Powered Phishing Detection
// Client-side Random Forest + LSTM simulation

class PhishGuard {
    constructor() {
        this.history = this.loadHistory();
        this.stats = {
            total: 0,
            safe: 0,
            suspicious: 0,
            phishing: 0
        };
        this.initStats();
        this.initCharts();
        this.initEventListeners();
        this.updateDashboard();
    }

    // Initialize statistics from history
    initStats() {
        this.history.forEach(entry => {
            this.stats.total++;
            this.stats[entry.verdict]++;
        });
    }

    // Initialize event listeners
    initEventListeners() {
        document.getElementById('scanBtn').addEventListener('click', () => this.scanURL());
        document.getElementById('urlInput').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.scanURL();
        });
        document.getElementById('reportForm').addEventListener('submit', (e) => this.submitReport(e));
    }

    // Hybrid Random Forest + LSTM URL Analysis
    scanURL() {
        const urlInput = document.getElementById('urlInput');
        const url = urlInput.value.trim();

        if (!url) {
            this.showResult('Please enter a URL', 'suspicious');
            return;
        }

        // Show loading state
        const scanBtn = document.getElementById('scanBtn');
        const originalText = scanBtn.textContent;
        scanBtn.innerHTML = '<span class="loading"></span> Analyzing...';
        scanBtn.disabled = true;

        // Simulate AI processing delay
        setTimeout(() => {
            const result = this.analyzeURL(url);
            this.displayResult(result);
            this.addToHistory(result);
            this.updateDashboard();

            // Reset button
            scanBtn.textContent = originalText;
            scanBtn.disabled = false;
        }, 1500);
    }

    // AI-Powered URL Analysis (Hybrid Random Forest + LSTM)
    analyzeURL(url) {
        const features = this.extractFeatures(url);
        
        // Random Forest: Feature-based classification
        const rfScore = this.randomForestClassifier(features);
        
        // LSTM: Pattern-based classification
        const lstmScore = this.lstmClassifier(url);
        
        // Hybrid fusion (weighted average)
        const finalScore = (rfScore * 0.6) + (lstmScore * 0.4);
        
        // Determine verdict
        let verdict, confidence;
        if (finalScore >= 0.7) {
            verdict = 'phishing';
            confidence = Math.min(95, Math.round(finalScore * 100));
        } else if (finalScore >= 0.4) {
            verdict = 'suspicious';
            confidence = Math.round(finalScore * 100);
        } else {
            verdict = 'safe';
            confidence = Math.min(95, Math.round((1 - finalScore) * 100));
        }

        return {
            url,
            verdict,
            confidence,
            riskScore: Math.round(finalScore * 100),
            timestamp: new Date().toISOString(),
            features
        };
    }

    // Extract URL features for Random Forest
    extractFeatures(url) {
        const features = {};
        
        try {
            const urlObj = new URL(url.startsWith('http') ? url : 'https://' + url);
            
            // Length features
            features.urlLength = url.length;
            features.domainLength = urlObj.hostname.length;
            features.pathLength = urlObj.pathname.length;
            
            // Character features
            features.numDots = (url.match(/\./g) || []).length;
            features.numHyphens = (url.match(/-/g) || []).length;
            features.numUnderscores = (url.match(/_/g) || []).length;
            features.numDigits = (url.match(/\d/g) || []).length;
            features.numSpecialChars = (url.match(/[^a-zA-Z0-9.-]/g) || []).length;
            
            // Security features
            features.hasHTTPS = urlObj.protocol === 'https:' ? 1 : 0;
            features.hasIP = /\d+\.\d+\.\d+\.\d+/.test(urlObj.hostname) ? 1 : 0;
            features.hasPort = urlObj.port ? 1 : 0;
            features.hasSubdomain = urlObj.hostname.split('.').length > 2 ? 1 : 0;
            
            // Suspicious patterns
            features.hasAtSymbol = url.includes('@') ? 1 : 0;
            features.hasDoubleSlash = url.split('//').length > 2 ? 1 : 0;
            
            // Phishing keywords
            const phishingKeywords = ['login', 'signin', 'account', 'verify', 'secure', 'update', 'confirm', 'banking'];
            features.hasPhishingKeyword = phishingKeywords.some(k => url.toLowerCase().includes(k)) ? 1 : 0;
            
            // Brand impersonation
            const brands = ['paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook'];
            features.hasBrandName = brands.some(b => urlObj.hostname.toLowerCase().includes(b)) ? 1 : 0;
            
        } catch (e) {
            // Invalid URL
            features.invalidURL = 1;
        }
        
        return features;
    }

    // Random Forest Classifier (simulated with decision rules)
    randomForestClassifier(features) {
        let score = 0;
        let count = 0;

        // Tree 1: URL Length Check
        if (features.urlLength > 75) score += 0.7;
        else if (features.urlLength > 50) score += 0.4;
        else score += 0.1;
        count++;

        // Tree 2: Security Features
        if (!features.hasHTTPS) score += 0.5;
        if (features.hasIP) score += 0.8;
        if (features.hasPort) score += 0.6;
        count++;

        // Tree 3: Suspicious Patterns
        if (features.hasAtSymbol) score += 0.9;
        if (features.hasDoubleSlash) score += 0.7;
        if (features.numHyphens > 3) score += 0.6;
        count++;

        // Tree 4: Character Analysis
        const specialRatio = features.numSpecialChars / features.urlLength;
        if (specialRatio > 0.15) score += 0.8;
        else if (specialRatio > 0.08) score += 0.5;
        count++;

        // Tree 5: Domain Analysis
        if (features.domainLength > 40) score += 0.7;
        if (features.numDots > 4) score += 0.6;
        if (features.hasSubdomain && features.hasBrandName) score += 0.9;
        count++;

        // Tree 6: Phishing Indicators
        if (features.hasPhishingKeyword) {
            if (!features.hasHTTPS) score += 0.9;
            else score += 0.4;
        }
        count++;

        // Tree 7: Invalid URL Check
        if (features.invalidURL) score += 1.0;
        count++;

        return score / count;
    }

    // LSTM Classifier (simulated with pattern matching)
    lstmClassifier(url) {
        let score = 0;
        
        // Encode URL as sequence
        const sequence = url.toLowerCase();
        
        // Pattern 1: Repetitive characters
        const repetitions = sequence.match(/(.)\1{2,}/g);
        if (repetitions && repetitions.length > 2) score += 0.3;
        
        // Pattern 2: Random string detection
        const randomPattern = /[a-z]{10,}/g;
        const matches = sequence.match(randomPattern);
        if (matches) {
            matches.forEach(match => {
                const uniqueChars = new Set(match).size;
                if (uniqueChars / match.length > 0.7) score += 0.2;
            });
        }
        
        // Pattern 3: Homograph attacks (lookalike characters)
        const homographs = ['рaypal', 'gооgle', 'аmazon', 'miсrosoft'];
        if (homographs.some(h => sequence.includes(h))) score += 0.9;
        
        // Pattern 4: Suspicious TLDs
        const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top'];
        if (suspiciousTLDs.some(tld => sequence.endsWith(tld))) score += 0.6;
        
        // Pattern 5: URL shorteners (potential redirect)
        const shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 'ow.ly', 't.co'];
        if (shorteners.some(s => sequence.includes(s))) score += 0.4;
        
        // Pattern 6: Obfuscation techniques
        if (sequence.includes('%20') || sequence.includes('%2f')) score += 0.3;
        if ((sequence.match(/%/g) || []).length > 3) score += 0.5;
        
        // Pattern 7: Sequential patterns
        const sequential = ['123', 'abc', '000', '111'];
        sequential.forEach(seq => {
            if (sequence.includes(seq)) score += 0.1;
        });
        
        return Math.min(1.0, score);
    }

    // Display scan result
    displayResult(result) {
        const resultDiv = document.getElementById('scanResult');
        const detailsDiv = document.getElementById('scanDetails');

        resultDiv.className = `scan-result ${result.verdict}`;
        resultDiv.classList.remove('hidden');

        let icon, message;
        switch (result.verdict) {
            case 'safe':
                icon = '✅';
                message = 'URL appears SAFE';
                break;
            case 'suspicious':
                icon = '⚠️';
                message = 'URL is SUSPICIOUS';
                break;
            case 'phishing':
                icon = '🚨';
                message = 'PHISHING DETECTED';
                break;
        }

        resultDiv.innerHTML = `
            <div style="font-size: 2rem; margin-bottom: 0.5rem;">${icon}</div>
            <div>${message}</div>
            <div style="font-size: 0.9rem; margin-top: 0.5rem; opacity: 0.8;">
                Confidence: ${result.confidence}%
            </div>
        `;

        // Show details
        detailsDiv.classList.remove('hidden');
        detailsDiv.innerHTML = `
            <strong>Analysis Details:</strong>
            <div class="detail-row">
                <span>URL Length:</span>
                <span>${result.features.urlLength} chars</span>
            </div>
            <div class="detail-row">
                <span>HTTPS Enabled:</span>
                <span>${result.features.hasHTTPS ? '✓ Yes' : '✗ No'}</span>
            </div>
            <div class="detail-row">
                <span>Risk Score:</span>
                <span>${result.riskScore}/100</span>
            </div>
            <div class="detail-row">
                <span>Detection Method:</span>
                <span>Hybrid RF + LSTM</span>
            </div>
        `;
    }

    // Show simple result message
    showResult(message, type) {
        const resultDiv = document.getElementById('scanResult');
        resultDiv.className = `scan-result ${type}`;
        resultDiv.classList.remove('hidden');
        resultDiv.textContent = message;
    }

    // Add scan to history
    addToHistory(result) {
        this.history.unshift(result);
        if (this.history.length > 50) {
            this.history = this.history.slice(0, 50);
        }
        this.saveHistory();
        
        // Update stats
        this.stats.total++;
        this.stats[result.verdict]++;
    }

    // Update dashboard
    updateDashboard() {
        // Update stat counters
        document.getElementById('totalScans').textContent = this.stats.total;
        document.getElementById('safeCount').textContent = this.stats.safe;
        document.getElementById('suspiciousCount').textContent = this.stats.suspicious;
        document.getElementById('phishingCount').textContent = this.stats.phishing;

        // Update history table
        this.updateHistoryTable();
        
        // Update charts
        this.updateCharts();
    }

    // Update history table
    updateHistoryTable() {
        const tbody = document.getElementById('historyBody');
        
        if (this.history.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="no-data">No scans yet. Start by analyzing a URL above!</td></tr>';
            return;
        }

        tbody.innerHTML = this.history.map(entry => {
            const date = new Date(entry.timestamp);
            const time = date.toLocaleString();
            const displayUrl = entry.url.length > 50 ? entry.url.substring(0, 50) + '...' : entry.url;
            
            return `
                <tr>
                    <td>${time}</td>
                    <td title="${entry.url}">${displayUrl}</td>
                    <td><span class="verdict-badge ${entry.verdict}">${entry.verdict.toUpperCase()}</span></td>
                    <td>${entry.confidence}%</td>
                    <td>${entry.riskScore}/100</td>
                </tr>
            `;
        }).join('');
    }

    // Initialize charts
    initCharts() {
        // Check if Chart.js is loaded
        if (typeof Chart === 'undefined') {
            console.warn('Chart.js not loaded, charts will be disabled');
            document.querySelectorAll('.chart-card canvas').forEach(canvas => {
                canvas.parentElement.innerHTML = '<div style="padding: 2rem; text-align: center; color: var(--text-secondary);">Charts loading...</div>';
            });
            // Retry after delay
            setTimeout(() => this.retryCharts(), 2000);
            return;
        }

        // Risk Distribution Chart
        const riskCtx = document.getElementById('riskChart').getContext('2d');
        this.riskChart = new Chart(riskCtx, {
            type: 'doughnut',
            data: {
                labels: ['Safe', 'Suspicious', 'Phishing'],
                datasets: [{
                    data: [0, 0, 0],
                    backgroundColor: [
                        'rgba(0, 255, 136, 0.7)',
                        'rgba(255, 170, 0, 0.7)',
                        'rgba(255, 0, 85, 0.7)'
                    ],
                    borderColor: [
                        '#00ff88',
                        '#ffaa00',
                        '#ff0055'
                    ],
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: '#e0e0e0',
                            font: { size: 12 }
                        }
                    }
                }
            }
        });

        // Timeline Chart
        const timelineCtx = document.getElementById('timelineChart').getContext('2d');
        this.timelineChart = new Chart(timelineCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Scans',
                    data: [],
                    borderColor: '#00ff88',
                    backgroundColor: 'rgba(0, 255, 136, 0.1)',
                    borderWidth: 2,
                    tension: 0.4,
                    fill: true
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        display: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            color: '#e0e0e0',
                            stepSize: 1
                        },
                        grid: {
                            color: 'rgba(255, 255, 255, 0.1)'
                        }
                    },
                    x: {
                        ticks: {
                            color: '#e0e0e0'
                        },
                        grid: {
                            color: 'rgba(255, 255, 255, 0.1)'
                        }
                    }
                }
            }
        });
    }

    // Retry initializing charts
    retryCharts() {
        if (typeof Chart !== 'undefined') {
            this.initCharts();
        }
    }

    // Update charts with current data
    updateCharts() {
        // Check if charts are initialized
        if (!this.riskChart || !this.timelineChart) {
            return;
        }

        // Update risk distribution
        this.riskChart.data.datasets[0].data = [
            this.stats.safe,
            this.stats.suspicious,
            this.stats.phishing
        ];
        this.riskChart.update();

        // Update timeline
        const timelineData = this.getTimelineData();
        this.timelineChart.data.labels = timelineData.labels;
        this.timelineChart.data.datasets[0].data = timelineData.data;
        this.timelineChart.update();
    }

    // Get timeline data for chart
    getTimelineData() {
        const labels = [];
        const data = [];
        const now = new Date();
        
        // Last 7 time periods
        for (let i = 6; i >= 0; i--) {
            const date = new Date(now);
            date.setHours(date.getHours() - i);
            
            const hourLabel = date.getHours() + ':00';
            labels.push(hourLabel);
            
            const count = this.history.filter(entry => {
                const entryDate = new Date(entry.timestamp);
                return entryDate.getHours() === date.getHours() &&
                       entryDate.getDate() === date.getDate();
            }).length;
            
            data.push(count);
        }
        
        return { labels, data };
    }

    // Submit threat report
    submitReport(e) {
        e.preventDefault();
        
        const url = document.getElementById('reportUrl').value;
        const type = document.getElementById('reportType').value;
        const details = document.getElementById('reportDetails').value;
        
        // Simulate report submission
        const resultDiv = document.getElementById('reportResult');
        resultDiv.className = 'report-result success';
        resultDiv.classList.remove('hidden');
        resultDiv.innerHTML = `
            <div style="font-size: 1.5rem; margin-bottom: 0.5rem;">✅</div>
            <div><strong>Report Submitted Successfully!</strong></div>
            <div style="font-size: 0.9rem; margin-top: 0.5rem; opacity: 0.8;">
                Thank you for helping protect the community. Our team will investigate this threat.
            </div>
        `;
        
        // Reset form
        document.getElementById('reportForm').reset();
        
        // Hide result after 5 seconds
        setTimeout(() => {
            resultDiv.classList.add('hidden');
        }, 5000);
    }

    // Local storage operations
    saveHistory() {
        localStorage.setItem('phishguard_history', JSON.stringify(this.history));
    }

    loadHistory() {
        const stored = localStorage.getItem('phishguard_history');
        return stored ? JSON.parse(stored) : [];
    }
}

// Initialize app when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    new PhishGuard();
});
