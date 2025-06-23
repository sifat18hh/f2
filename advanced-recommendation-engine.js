
const fs = require('fs');

class AdvancedRecommendationEngine {
    constructor() {
        this.userProfiles = new Map();
        this.videoFeatures = new Map();
        this.interactionMatrix = new Map();
        this.contentCategories = new Map();
        this.trendingTopics = new Set();
        this.collaborativeFilters = new Map();
        
        this.initializeEngine();
        console.log('🤖 Advanced Recommendation Engine initialized');
    }

    initializeEngine() {
        // Load existing data
        this.loadUserProfiles();
        this.loadVideoFeatures();
        this.loadInteractionData();
        this.updateTrendingTopics();
        
        // Start real-time learning
        this.startRealTimeLearning();
    }

    // Enhanced User Profiling
    createUserProfile(userId, initialData = {}) {
        const profile = {
            userId: userId,
            preferences: {
                categories: new Map(),
                tags: new Map(),
                durations: { short: 0, medium: 0, long: 0 },
                timeOfDay: new Map(),
                engagement: { likes: 0, comments: 0, shares: 0, watchTime: 0 }
            },
            behavior: {
                watchHistory: [],
                searchHistory: [],
                clickPatterns: [],
                sessionDuration: [],
                deviceType: 'unknown'
            },
            demographics: {
                ageGroup: 'unknown',
                language: 'bn',
                location: 'BD',
                timezone: 'Asia/Dhaka'
            },
            interests: new Set(),
            disinterests: new Set(),
            lastActivity: new Date(),
            profileStrength: 0,
            ...initialData
        };

        this.userProfiles.set(userId, profile);
        return profile;
    }

    // Advanced Video Feature Extraction
    extractVideoFeatures(video) {
        const features = {
            id: video.id,
            title: video.title,
            description: video.description,
            category: video.category,
            tags: video.tags || [],
            duration: this.categorizeVideoDuration(video.duration),
            uploadDate: new Date(video.uploadDate),
            metrics: {
                views: video.views || 0,
                likes: video.likes || 0,
                dislikes: video.dislikes || 0,
                comments: (video.comments || []).length,
                shares: video.shares || 0
            },
            content: {
                language: this.detectLanguage(video.title, video.description),
                sentiment: this.analyzeSentiment(video.title, video.description),
                topics: this.extractTopics(video.title, video.description, video.tags),
                complexity: this.analyzeContentComplexity(video.description)
            },
            quality: {
                resolution: video.resolution || 'HD',
                thumbnail: video.thumbnail,
                audioQuality: 'good'
            },
            engagement: {
                ctr: this.calculateCTR(video),
                retentionRate: this.calculateRetention(video),
                viralityScore: this.calculateVirality(video),
                freshness: this.calculateFreshness(video.uploadDate)
            }
        };

        this.videoFeatures.set(video.id, features);
        return features;
    }

    // Intelligent Recommendation Algorithm
    async generateRecommendations(userId, options = {}) {
        const {
            count = 20,
            includeCategories = [],
            excludeCategories = [],
            timeContext = 'any',
            deviceType = 'web'
        } = options;

        console.log(`🎯 Generating ${count} recommendations for user ${userId}`);

        try {
            // Get or create user profile
            let userProfile = this.userProfiles.get(userId);
            if (!userProfile) {
                userProfile = this.createUserProfile(userId);
            }

            // Multi-algorithm approach
            const algorithms = [
                { name: 'collaborative', weight: 0.25, fn: this.collaborativeFiltering },
                { name: 'content', weight: 0.25, fn: this.contentBasedFiltering },
                { name: 'hybrid', weight: 0.20, fn: this.hybridFiltering },
                { name: 'trending', weight: 0.10, fn: this.trendingBasedFiltering },
                { name: 'behavioral', weight: 0.10, fn: this.behavioralFiltering },
                { name: 'contextual', weight: 0.10, fn: this.contextualFiltering }
            ];

            const allVideos = this.getAllVideos();
            const candidateVideos = this.filterCandidates(allVideos, userProfile, {
                includeCategories,
                excludeCategories,
                timeContext
            });

            // Apply each algorithm and combine scores
            const videoScores = new Map();

            for (const algorithm of algorithms) {
                const scores = await algorithm.fn.call(this, userProfile, candidateVideos, options);
                
                for (const [videoId, score] of scores) {
                    const currentScore = videoScores.get(videoId) || 0;
                    videoScores.set(videoId, currentScore + (score * algorithm.weight));
                }
            }

            // Apply post-processing
            const recommendations = this.postProcessRecommendations(videoScores, userProfile, {
                count,
                diversityBoost: true,
                freshnessBoost: true,
                qualityFilter: true
            });

            // Update user profile with recommendation context
            this.updateUserProfileFromRecommendations(userProfile, recommendations);

            console.log(`✅ Generated ${recommendations.length} personalized recommendations`);
            return recommendations;

        } catch (error) {
            console.error('❌ Recommendation generation error:', error);
            return this.getFallbackRecommendations(count);
        }
    }

    // Collaborative Filtering Algorithm
    async collaborativeFiltering(userProfile, candidateVideos, options) {
        const scores = new Map();
        const userSimilarities = this.findSimilarUsers(userProfile);

        for (const video of candidateVideos) {
            let score = 0;
            let weightSum = 0;

            for (const [similarUserId, similarity] of userSimilarities) {
                const similarUserProfile = this.userProfiles.get(similarUserId);
                if (similarUserProfile) {
                    const userVideoScore = this.getUserVideoScore(similarUserProfile, video);
                    score += similarity * userVideoScore;
                    weightSum += similarity;
                }
            }

            if (weightSum > 0) {
                scores.set(video.id, score / weightSum);
            }
        }

        return scores;
    }

    // Content-Based Filtering Algorithm
    async contentBasedFiltering(userProfile, candidateVideos, options) {
        const scores = new Map();

        for (const video of candidateVideos) {
            const videoFeatures = this.videoFeatures.get(video.id);
            if (!videoFeatures) continue;

            let score = 0;

            // Category preference
            const categoryPref = userProfile.preferences.categories.get(video.category) || 0;
            score += categoryPref * 0.3;

            // Tag matching
            let tagScore = 0;
            for (const tag of videoFeatures.tags) {
                const tagPref = userProfile.preferences.tags.get(tag) || 0;
                tagScore += tagPref;
            }
            score += (tagScore / Math.max(videoFeatures.tags.length, 1)) * 0.25;

            // Duration preference
            const durationPref = userProfile.preferences.durations[videoFeatures.duration] || 0;
            score += durationPref * 0.15;

            // Topic similarity
            const topicSimilarity = this.calculateTopicSimilarity(userProfile.interests, videoFeatures.content.topics);
            score += topicSimilarity * 0.2;

            // Quality factor
            score += videoFeatures.engagement.viralityScore * 0.1;

            scores.set(video.id, Math.max(0, Math.min(1, score)));
        }

        return scores;
    }

    // Hybrid Filtering (Matrix Factorization + Deep Learning approach)
    async hybridFiltering(userProfile, candidateVideos, options) {
        const scores = new Map();
        
        for (const video of candidateVideos) {
            const videoFeatures = this.videoFeatures.get(video.id);
            if (!videoFeatures) continue;

            // Feature vector creation
            const userVector = this.createUserFeatureVector(userProfile);
            const videoVector = this.createVideoFeatureVector(videoFeatures);

            // Cosine similarity
            const similarity = this.cosineSimilarity(userVector, videoVector);
            
            // Adjust based on user's historical preferences
            const personalityAdjustment = this.calculatePersonalityAdjustment(userProfile, videoFeatures);
            
            const finalScore = similarity * personalityAdjustment;
            scores.set(video.id, finalScore);
        }

        return scores;
    }

    // Trending-Based Filtering
    async trendingBasedFiltering(userProfile, candidateVideos, options) {
        const scores = new Map();
        const now = new Date();

        for (const video of candidateVideos) {
            const videoFeatures = this.videoFeatures.get(video.id);
            if (!videoFeatures) continue;

            let trendingScore = 0;

            // Recent engagement
            const timeSinceUpload = now - videoFeatures.uploadDate;
            const hoursSinceUpload = timeSinceUpload / (1000 * 60 * 60);
            
            if (hoursSinceUpload < 24) {
                trendingScore += 0.4; // New content boost
            } else if (hoursSinceUpload < 168) { // 1 week
                trendingScore += 0.2;
            }

            // Engagement velocity
            const engagementRate = (videoFeatures.metrics.likes + videoFeatures.metrics.comments) / 
                                 Math.max(videoFeatures.metrics.views, 1);
            trendingScore += Math.min(engagementRate * 2, 0.3);

            // Viral potential
            trendingScore += videoFeatures.engagement.viralityScore * 0.3;

            scores.set(video.id, Math.max(0, Math.min(1, trendingScore)));
        }

        return scores;
    }

    // Behavioral Pattern Filtering
    async behavioralFiltering(userProfile, candidateVideos, options) {
        const scores = new Map();
        const currentHour = new Date().getHours();

        for (const video of candidateVideos) {
            const videoFeatures = this.videoFeatures.get(video.id);
            if (!videoFeatures) continue;

            let behaviorScore = 0;

            // Time-based preferences
            const timePreference = userProfile.preferences.timeOfDay.get(currentHour) || 0;
            behaviorScore += timePreference * 0.2;

            // Session pattern matching
            const sessionPattern = this.analyzeSessionPattern(userProfile);
            const videoFitsPattern = this.doesVideoFitPattern(videoFeatures, sessionPattern);
            behaviorScore += videoFitsPattern ? 0.3 : 0;

            // Engagement prediction
            const predictedEngagement = this.predictUserEngagement(userProfile, videoFeatures);
            behaviorScore += predictedEngagement * 0.5;

            scores.set(video.id, Math.max(0, Math.min(1, behaviorScore)));
        }

        return scores;
    }

    // Contextual Filtering
    async contextualFiltering(userProfile, candidateVideos, options) {
        const scores = new Map();
        const context = this.getCurrentContext(userProfile, options);

        for (const video of candidateVideos) {
            const videoFeatures = this.videoFeatures.get(video.id);
            if (!videoFeatures) continue;

            let contextScore = 0;

            // Device optimization
            if (context.deviceType === 'mobile' && videoFeatures.duration === 'short') {
                contextScore += 0.3;
            } else if (context.deviceType === 'desktop' && videoFeatures.duration === 'long') {
                contextScore += 0.2;
            }

            // Time context
            if (context.timeOfDay === 'morning' && videoFeatures.content.sentiment === 'positive') {
                contextScore += 0.2;
            } else if (context.timeOfDay === 'evening' && videoFeatures.category === 'entertainment') {
                contextScore += 0.3;
            }

            // Location/cultural context
            if (videoFeatures.content.language === userProfile.demographics.language) {
                contextScore += 0.2;
            }

            scores.set(video.id, Math.max(0, Math.min(1, contextScore)));
        }

        return scores;
    }

    // Real-time Learning System
    startRealTimeLearning() {
        // Update user profiles every minute
        setInterval(() => {
            this.updateAllUserProfiles();
        }, 60000);

        // Recalculate video features every 5 minutes
        setInterval(() => {
            this.updateVideoFeatures();
        }, 300000);

        // Update trending topics every 15 minutes
        setInterval(() => {
            this.updateTrendingTopics();
        }, 900000);

        console.log('📚 Real-time learning system started');
    }

    // User Interaction Learning
    learnFromInteraction(userId, videoId, interactionType, metadata = {}) {
        const userProfile = this.userProfiles.get(userId);
        if (!userProfile) return;

        const videoFeatures = this.videoFeatures.get(videoId);
        if (!videoFeatures) return;

        // Record interaction
        const interaction = {
            videoId,
            type: interactionType,
            timestamp: new Date(),
            metadata
        };

        // Update user preferences based on interaction
        switch (interactionType) {
            case 'view':
                this.updatePreferencesFromView(userProfile, videoFeatures, metadata);
                break;
            case 'like':
                this.updatePreferencesFromLike(userProfile, videoFeatures);
                break;
            case 'dislike':
                this.updatePreferencesFromDislike(userProfile, videoFeatures);
                break;
            case 'comment':
                this.updatePreferencesFromComment(userProfile, videoFeatures, metadata);
                break;
            case 'share':
                this.updatePreferencesFromShare(userProfile, videoFeatures);
                break;
            case 'skip':
                this.updatePreferencesFromSkip(userProfile, videoFeatures, metadata);
                break;
        }

        // Update interaction matrix for collaborative filtering
        this.updateInteractionMatrix(userId, videoId, interactionType, metadata);

        console.log(`📝 Learned from ${interactionType} interaction: User ${userId} -> Video ${videoId}`);
    }

    // Helper Methods
    findSimilarUsers(userProfile, limit = 50) {
        const similarities = new Map();

        for (const [userId, otherProfile] of this.userProfiles) {
            if (userId === userProfile.userId) continue;

            const similarity = this.calculateUserSimilarity(userProfile, otherProfile);
            if (similarity > 0.1) {
                similarities.set(userId, similarity);
            }
        }

        return new Map([...similarities.entries()]
            .sort((a, b) => b[1] - a[1])
            .slice(0, limit));
    }

    calculateUserSimilarity(user1, user2) {
        let similarity = 0;
        let factors = 0;

        // Category preferences similarity
        const categorySum = this.mapSimilarity(user1.preferences.categories, user2.preferences.categories);
        similarity += categorySum * 0.3;
        factors += 0.3;

        // Tag preferences similarity
        const tagSum = this.mapSimilarity(user1.preferences.tags, user2.preferences.tags);
        similarity += tagSum * 0.25;
        factors += 0.25;

        // Interest similarity
        const interestSum = this.setSimilarity(user1.interests, user2.interests);
        similarity += interestSum * 0.2;
        factors += 0.2;

        // Behavioral similarity
        const behaviorSum = this.behaviorSimilarity(user1.behavior, user2.behavior);
        similarity += behaviorSum * 0.15;
        factors += 0.15;

        // Demographic similarity
        const demoSum = this.demographicSimilarity(user1.demographics, user2.demographics);
        similarity += demoSum * 0.1;
        factors += 0.1;

        return factors > 0 ? similarity / factors : 0;
    }

    postProcessRecommendations(videoScores, userProfile, options) {
        const { count, diversityBoost, freshnessBoost, qualityFilter } = options;

        // Convert to array and sort
        let recommendations = Array.from(videoScores.entries())
            .map(([videoId, score]) => ({
                videoId,
                score,
                video: this.getVideoById(videoId),
                features: this.videoFeatures.get(videoId)
            }))
            .filter(item => item.video && item.features)
            .sort((a, b) => b.score - a.score);

        // Apply diversity boost
        if (diversityBoost) {
            recommendations = this.applyDiversityBoost(recommendations, userProfile);
        }

        // Apply freshness boost
        if (freshnessBoost) {
            recommendations = this.applyFreshnessBoost(recommendations);
        }

        // Apply quality filter
        if (qualityFilter) {
            recommendations = this.applyQualityFilter(recommendations);
        }

        // Remove already watched videos
        recommendations = recommendations.filter(item => 
            !userProfile.behavior.watchHistory.includes(item.videoId)
        );

        // Limit and return
        return recommendations.slice(0, count).map(item => ({
            ...item.video,
            recommendationScore: item.score,
            recommendationReason: this.generateRecommendationReason(item, userProfile)
        }));
    }

    generateRecommendationReason(item, userProfile) {
        const reasons = [];
        
        if (item.features.category && userProfile.preferences.categories.has(item.features.category)) {
            reasons.push(`আপনি ${item.features.category} ক্যাটাগরির ভিডিও পছন্দ করেন`);
        }

        if (item.features.engagement.viralityScore > 0.7) {
            reasons.push('ট্রেন্ডিং ভিডিও');
        }

        if (item.features.engagement.freshness > 0.8) {
            reasons.push('নতুন আপলোড');
        }

        return reasons.length > 0 ? reasons.join(', ') : 'আপনার জন্য সুপারিশকৃত';
    }

    // Data persistence methods
    saveUserProfiles() {
        const data = Array.from(this.userProfiles.entries()).map(([userId, profile]) => ({
            userId,
            ...profile,
            interests: Array.from(profile.interests),
            disinterests: Array.from(profile.disinterests)
        }));
        
        fs.writeFileSync('user-profiles.json', JSON.stringify(data, null, 2));
    }

    loadUserProfiles() {
        try {
            if (fs.existsSync('user-profiles.json')) {
                const data = JSON.parse(fs.readFileSync('user-profiles.json', 'utf8'));
                data.forEach(profile => {
                    profile.interests = new Set(profile.interests || []);
                    profile.disinterests = new Set(profile.disinterests || []);
                    this.userProfiles.set(profile.userId, profile);
                });
            }
        } catch (error) {
            console.error('Error loading user profiles:', error);
        }
    }

    // Utility methods
    getAllVideos() {
        try {
            if (fs.existsSync('videos.json')) {
                return JSON.parse(fs.readFileSync('videos.json', 'utf8'));
            }
        } catch (error) {
            console.error('Error loading videos:', error);
        }
        return [];
    }

    getVideoById(videoId) {
        const videos = this.getAllVideos();
        return videos.find(video => video.id == videoId);
    }

    categorizeVideoDuration(duration) {
        if (!duration) return 'medium';
        
        const minutes = this.parseDuration(duration);
        if (minutes < 5) return 'short';
        if (minutes > 20) return 'long';
        return 'medium';
    }

    parseDuration(duration) {
        if (typeof duration === 'string') {
            const parts = duration.split(':');
            if (parts.length === 2) {
                return parseInt(parts[0]) + (parseInt(parts[1]) / 60);
            }
        }
        return 10; // default
    }

    detectLanguage(title, description) {
        const banglaPattern = /[\u0980-\u09FF]/;
        if (banglaPattern.test(title) || banglaPattern.test(description)) {
            return 'bn';
        }
        return 'en';
    }

    analyzeSentiment(title, description) {
        const positiveWords = ['ভালো', 'সুন্দর', 'দারুণ', 'চমৎকার', 'amazing', 'great', 'awesome', 'beautiful'];
        const negativeWords = ['খারাপ', 'বাজে', 'দুঃখজনক', 'bad', 'terrible', 'awful', 'sad'];
        
        const text = (title + ' ' + description).toLowerCase();
        
        let positiveCount = 0;
        let negativeCount = 0;
        
        positiveWords.forEach(word => {
            if (text.includes(word)) positiveCount++;
        });
        
        negativeWords.forEach(word => {
            if (text.includes(word)) negativeCount++;
        });
        
        if (positiveCount > negativeCount) return 'positive';
        if (negativeCount > positiveCount) return 'negative';
        return 'neutral';
    }

    calculateCTR(video) {
        const impressions = video.views * 1.5; // Estimated impressions
        return video.views / Math.max(impressions, 1);
    }

    calculateRetention(video) {
        // Simulate retention based on likes/views ratio
        return Math.min(video.likes / Math.max(video.views, 1) * 10, 1);
    }

    calculateVirality(video) {
        const ageInDays = (new Date() - new Date(video.uploadDate)) / (1000 * 60 * 60 * 24);
        const dailyViews = video.views / Math.max(ageInDays, 0.1);
        
        // Normalize to 0-1 scale
        return Math.min(dailyViews / 10000, 1);
    }

    calculateFreshness(uploadDate) {
        const ageInHours = (new Date() - new Date(uploadDate)) / (1000 * 60 * 60);
        return Math.max(0, 1 - (ageInHours / (24 * 7))); // Decays over a week
    }

    cosineSimilarity(vectorA, vectorB) {
        if (vectorA.length !== vectorB.length) return 0;
        
        let dotProduct = 0;
        let normA = 0;
        let normB = 0;
        
        for (let i = 0; i < vectorA.length; i++) {
            dotProduct += vectorA[i] * vectorB[i];
            normA += vectorA[i] * vectorA[i];
            normB += vectorB[i] * vectorB[i];
        }
        
        const denominator = Math.sqrt(normA) * Math.sqrt(normB);
        return denominator === 0 ? 0 : dotProduct / denominator;
    }

    // More utility methods would be implemented here...
    
    getFallbackRecommendations(count) {
        const videos = this.getAllVideos();
        return videos
            .sort((a, b) => (b.views + b.likes) - (a.views + a.likes))
            .slice(0, count)
            .map(video => ({
                ...video,
                recommendationScore: 0.5,
                recommendationReason: 'জনপ্রিয় ভিডিও'
            }));
    }
}

module.exports = AdvancedRecommendationEngine;
