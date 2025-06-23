
const fs = require('fs');

class RecommendationAnalytics {
    constructor() {
        this.metrics = {
            totalRecommendations: 0,
            clickThroughRate: 0,
            userEngagement: new Map(),
            algorithmPerformance: new Map(),
            categoryPerformance: new Map(),
            devicePerformance: new Map()
        };
        
        this.initialize();
    }

    initialize() {
        this.loadAnalytics();
        this.startAnalyticsCollection();
        console.log('📊 Recommendation Analytics initialized');
    }

    trackRecommendationShown(userId, videoId, algorithm, position) {
        const event = {
            type: 'recommendation_shown',
            userId,
            videoId,
            algorithm,
            position,
            timestamp: new Date()
        };

        this.recordEvent(event);
        this.metrics.totalRecommendations++;
    }

    trackRecommendationClicked(userId, videoId, algorithm, position, timeToClick) {
        const event = {
            type: 'recommendation_clicked',
            userId,
            videoId,
            algorithm,
            position,
            timeToClick,
            timestamp: new Date()
        };

        this.recordEvent(event);
        this.updateClickThroughRate(algorithm);
    }

    trackVideoWatched(userId, videoId, watchDuration, totalDuration) {
        const watchPercentage = (watchDuration / totalDuration) * 100;
        
        const event = {
            type: 'video_watched',
            userId,
            videoId,
            watchDuration,
            totalDuration,
            watchPercentage,
            timestamp: new Date()
        };

        this.recordEvent(event);
        this.updateEngagementMetrics(userId, watchPercentage);
    }

    generateAnalyticsReport() {
        const events = this.loadEvents();
        const report = {
            generatedAt: new Date(),
            summary: {
                totalRecommendations: this.metrics.totalRecommendations,
                totalClicks: events.filter(e => e.type === 'recommendation_clicked').length,
                averageCTR: this.calculateAverageCTR(events),
                topPerformingAlgorithm: this.getTopPerformingAlgorithm(events),
                userEngagementScore: this.calculateUserEngagementScore(events)
            },
            algorithms: this.analyzeAlgorithmPerformance(events),
            categories: this.analyzeCategoryPerformance(events),
            devices: this.analyzeDevicePerformance(events),
            timeBasedAnalysis: this.analyzeTimePatterns(events),
            recommendations: this.generateImprovementRecommendations(events)
        };

        this.saveReport(report);
        return report;
    }

    calculateAverageCTR(events) {
        const shown = events.filter(e => e.type === 'recommendation_shown');
        const clicked = events.filter(e => e.type === 'recommendation_clicked');
        
        return shown.length > 0 ? (clicked.length / shown.length) * 100 : 0;
    }

    getTopPerformingAlgorithm(events) {
        const algorithmStats = new Map();
        
        events.forEach(event => {
            if (!algorithmStats.has(event.algorithm)) {
                algorithmStats.set(event.algorithm, { shown: 0, clicked: 0 });
            }
            
            const stats = algorithmStats.get(event.algorithm);
            if (event.type === 'recommendation_shown') stats.shown++;
            if (event.type === 'recommendation_clicked') stats.clicked++;
        });

        let bestAlgorithm = null;
        let bestCTR = 0;

        for (const [algorithm, stats] of algorithmStats) {
            const ctr = stats.shown > 0 ? (stats.clicked / stats.shown) * 100 : 0;
            if (ctr > bestCTR) {
                bestCTR = ctr;
                bestAlgorithm = algorithm;
            }
        }

        return { algorithm: bestAlgorithm, ctr: bestCTR };
    }

    analyzeAlgorithmPerformance(events) {
        const algorithms = ['collaborative', 'content', 'hybrid', 'trending', 'behavioral', 'contextual'];
        const performance = {};

        algorithms.forEach(algorithm => {
            const shown = events.filter(e => e.type === 'recommendation_shown' && e.algorithm === algorithm);
            const clicked = events.filter(e => e.type === 'recommendation_clicked' && e.algorithm === algorithm);
            
            performance[algorithm] = {
                recommendationsShown: shown.length,
                clicks: clicked.length,
                ctr: shown.length > 0 ? (clicked.length / shown.length) * 100 : 0,
                avgTimeToClick: this.calculateAvgTimeToClick(clicked),
                positionAnalysis: this.analyzePositionPerformance(shown, clicked)
            };
        });

        return performance;
    }

    generateImprovementRecommendations(events) {
        const recommendations = [];
        const ctr = this.calculateAverageCTR(events);

        if (ctr < 5) {
            recommendations.push({
                type: 'low_ctr',
                message: 'Click-through rate is below 5%. Consider improving recommendation relevance.',
                priority: 'high',
                suggestions: [
                    'Increase personalization weight',
                    'Improve content-based filtering',
                    'Add more user interaction data collection'
                ]
            });
        }

        const algorithmPerf = this.analyzeAlgorithmPerformance(events);
        const poorPerformingAlgorithms = Object.entries(algorithmPerf)
            .filter(([_, perf]) => perf.ctr < 3)
            .map(([algorithm, _]) => algorithm);

        if (poorPerformingAlgorithms.length > 0) {
            recommendations.push({
                type: 'poor_algorithm_performance',
                message: `Algorithms ${poorPerformingAlgorithms.join(', ')} are underperforming.`,
                priority: 'medium',
                suggestions: [
                    'Adjust algorithm weights',
                    'Improve feature extraction',
                    'Add more training data'
                ]
            });
        }

        return recommendations;
    }

    recordEvent(event) {
        const eventsFile = 'recommendation-events.json';
        let events = [];

        if (fs.existsSync(eventsFile)) {
            events = JSON.parse(fs.readFileSync(eventsFile, 'utf8'));
        }

        events.push(event);

        // Keep only last 10000 events
        if (events.length > 10000) {
            events = events.slice(-10000);
        }

        fs.writeFileSync(eventsFile, JSON.stringify(events, null, 2));
    }

    loadEvents() {
        const eventsFile = 'recommendation-events.json';
        if (fs.existsSync(eventsFile)) {
            return JSON.parse(fs.readFileSync(eventsFile, 'utf8'));
        }
        return [];
    }

    saveReport(report) {
        const filename = `recommendation-analytics-${Date.now()}.json`;
        fs.writeFileSync(filename, JSON.stringify(report, null, 2));
        console.log(`📊 Analytics report saved: ${filename}`);
    }

    loadAnalytics() {
        try {
            const files = fs.readdirSync('.')
                .filter(file => file.startsWith('recommendation-analytics-'))
                .sort()
                .slice(-1);

            if (files.length > 0) {
                const data = JSON.parse(fs.readFileSync(files[0], 'utf8'));
                this.metrics = { ...this.metrics, ...data.summary };
            }
        } catch (error) {
            console.warn('Could not load previous analytics:', error.message);
        }
    }

    startAnalyticsCollection() {
        // Generate analytics report every hour
        setInterval(() => {
            this.generateAnalyticsReport();
        }, 3600000);

        console.log('📈 Analytics collection started');
    }
}

module.exports = RecommendationAnalytics;
