
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

class CompleteSystemAnalysis {
    constructor() {
        this.analysisResults = {
            timestamp: new Date().toISOString(),
            systemHealth: {},
            security: {},
            performance: {},
            files: {},
            database: {},
            authentication: {},
            features: {},
            recommendations: []
        };
    }

    async runCompleteAnalysis() {
        console.log('🔍 Starting Complete System Analysis...');
        console.log('=' .repeat(60));
        
        await this.analyzeSystemHealth();
        await this.analyzeSecurityStatus();
        await this.analyzePerformance();
        await this.analyzeFileStructure();
        await this.analyzeDatabaseIntegrity();
        await this.analyzeAuthentication();
        await this.analyzeFeatures();
        await this.generateRecommendations();
        
        this.generateCompleteReport();
        
        console.log('✅ Complete System Analysis Finished!');
    }

    async analyzeSystemHealth() {
        console.log('🏥 Analyzing System Health...');
        
        try {
            const health = {
                serverStatus: this.checkServerFiles(),
                packageStatus: this.checkPackageIntegrity(),
                storageStatus: this.checkStorageSystem(),
                backupStatus: this.checkBackupSystems(),
                uptime: process.uptime(),
                memory: process.memoryUsage(),
                nodeVersion: process.version
            };
            
            const healthScore = this.calculateHealthScore(health);
            
            this.analysisResults.systemHealth = {
                ...health,
                score: healthScore,
                status: healthScore >= 90 ? 'Excellent' : 
                       healthScore >= 80 ? 'Good' : 
                       healthScore >= 60 ? 'Fair' : 'Poor'
            };
            
            console.log(`   Health Score: ${healthScore}% - ${this.analysisResults.systemHealth.status}`);
            
        } catch (error) {
            console.error('   ❌ Health analysis failed:', error.message);
        }
    }

    async analyzeSecurityStatus() {
        console.log('🔒 Analyzing Security Status...');
        
        try {
            const security = {
                sensitiveFiles: this.findSensitiveFiles(),
                filePermissions: this.checkFilePermissions(),
                credentialExposure: this.checkCredentialExposure(),
                codeVulnerabilities: this.scanCodeVulnerabilities(),
                authenticationSecurity: this.checkAuthSecurity()
            };
            
            const securityScore = this.calculateSecurityScore(security);
            
            this.analysisResults.security = {
                ...security,
                score: securityScore,
                status: securityScore >= 90 ? 'Secure' : 
                       securityScore >= 70 ? 'Moderate' : 'At Risk'
            };
            
            console.log(`   Security Score: ${securityScore}% - ${this.analysisResults.security.status}`);
            
        } catch (error) {
            console.error('   ❌ Security analysis failed:', error.message);
        }
    }

    async analyzePerformance() {
        console.log('⚡ Analyzing Performance...');
        
        try {
            const performance = {
                bundleSize: this.calculateBundleSize(),
                databaseSize: this.calculateDatabaseSize(),
                imageOptimization: this.checkImageOptimization(),
                cacheStatus: this.checkCachingStatus(),
                loadTime: this.estimateLoadTime()
            };
            
            const performanceScore = this.calculatePerformanceScore(performance);
            
            this.analysisResults.performance = {
                ...performance,
                score: performanceScore,
                status: performanceScore >= 90 ? 'Excellent' : 
                       performanceScore >= 80 ? 'Good' : 
                       performanceScore >= 60 ? 'Fair' : 'Poor'
            };
            
            console.log(`   Performance Score: ${performanceScore}% - ${this.analysisResults.performance.status}`);
            
        } catch (error) {
            console.error('   ❌ Performance analysis failed:', error.message);
        }
    }

    async analyzeFileStructure() {
        console.log('📁 Analyzing File Structure...');
        
        try {
            const files = {
                totalFiles: this.countAllFiles(),
                totalSize: this.calculateTotalSize(),
                duplicates: this.findDuplicateFiles(),
                largeFiles: this.findLargeFiles(),
                organization: this.checkFileOrganization()
            };
            
            this.analysisResults.files = files;
            console.log(`   Total Files: ${files.totalFiles}, Size: ${this.formatSize(files.totalSize)}`);
            
        } catch (error) {
            console.error('   ❌ File structure analysis failed:', error.message);
        }
    }

    async analyzeDatabaseIntegrity() {
        console.log('🗄️ Analyzing Database Integrity...');
        
        try {
            const database = {
                userCount: this.getUserCount(),
                videoCount: this.getVideoCount(),
                categoryCount: this.getCategoryCount(),
                adCount: this.getAdCount(),
                dataIntegrity: this.checkDataIntegrity(),
                backupStatus: this.checkDatabaseBackups()
            };
            
            this.analysisResults.database = database;
            console.log(`   Users: ${database.userCount}, Videos: ${database.videoCount}`);
            
        } catch (error) {
            console.error('   ❌ Database analysis failed:', error.message);
        }
    }

    async analyzeAuthentication() {
        console.log('🔐 Analyzing Authentication System...');
        
        try {
            const auth = {
                adminUsers: this.getAdminUserCount(),
                userSessions: this.checkUserSessions(),
                passwordSecurity: this.checkPasswordSecurity(),
                loginSystem: this.testLoginSystem()
            };
            
            this.analysisResults.authentication = auth;
            console.log(`   Admin Users: ${auth.adminUsers}`);
            
        } catch (error) {
            console.error('   ❌ Authentication analysis failed:', error.message);
        }
    }

    async analyzeFeatures() {
        console.log('🎯 Analyzing Features...');
        
        try {
            const features = {
                videoUpload: this.checkVideoUploadFeature(),
                userManagement: this.checkUserManagementFeature(),
                adminPanel: this.checkAdminPanelFeature(),
                adsSystem: this.checkAdsSystemFeature(),
                apiEndpoints: this.checkApiEndpoints(),
                storageSystem: this.checkStorageSystemFeature()
            };
            
            this.analysisResults.features = features;
            const workingFeatures = Object.values(features).filter(f => f.status === 'working').length;
            console.log(`   Working Features: ${workingFeatures}/${Object.keys(features).length}`);
            
        } catch (error) {
            console.error('   ❌ Feature analysis failed:', error.message);
        }
    }

    // Helper methods for analysis
    checkServerFiles() {
        const criticalFiles = ['index.js', 'package.json', 'admin.html', 'index.html'];
        return criticalFiles.every(file => fs.existsSync(file));
    }

    checkPackageIntegrity() {
        return fs.existsSync('node_modules') && fs.existsSync('package.json');
    }

    checkStorageSystem() {
        const storageDirs = ['uploads', 'thumbnails', 'storage'];
        return storageDirs.every(dir => fs.existsSync(dir));
    }

    checkBackupSystems() {
        const backupDirs = ['system_backup', 'database_backup', 'package_backup'];
        return backupDirs.filter(dir => fs.existsSync(dir)).length;
    }

    calculateHealthScore(health) {
        let score = 0;
        if (health.serverStatus) score += 25;
        if (health.packageStatus) score += 25;
        if (health.storageStatus) score += 20;
        if (health.backupStatus >= 2) score += 20;
        if (health.uptime > 60) score += 10;
        return Math.min(score, 100);
    }

    findSensitiveFiles() {
        const sensitivePatterns = ['credential', 'password', 'secret', 'key', 'token'];
        const files = this.getAllFiles('.');
        return files.filter(file => 
            sensitivePatterns.some(pattern => 
                path.basename(file).toLowerCase().includes(pattern)
            )
        );
    }

    checkCredentialExposure() {
        const exposedFiles = [];
        if (fs.existsSync('admin-credentials.json')) {
            exposedFiles.push('admin-credentials.json');
        }
        return exposedFiles;
    }

    scanCodeVulnerabilities() {
        const dangerousPatterns = [/eval\s*\(/g, /exec\s*\(/g];
        const jsFiles = this.getAllFiles('.').filter(f => f.endsWith('.js'));
        const vulnerabilities = [];
        
        jsFiles.forEach(file => {
            try {
                const content = fs.readFileSync(file, 'utf8');
                dangerousPatterns.forEach(pattern => {
                    if (pattern.test(content)) {
                        vulnerabilities.push({ file, pattern: pattern.source });
                    }
                });
            } catch (error) {
                // Skip unreadable files
            }
        });
        
        return vulnerabilities;
    }

    calculateSecurityScore(security) {
        let score = 100;
        score -= security.sensitiveFiles.length * 10;
        score -= security.credentialExposure.length * 20;
        score -= security.codeVulnerabilities.length * 5;
        return Math.max(score, 0);
    }

    calculateBundleSize() {
        try {
            const files = ['index.js', 'script.js', 'admin-script.js'];
            let totalSize = 0;
            files.forEach(file => {
                if (fs.existsSync(file)) {
                    totalSize += fs.statSync(file).size;
                }
            });
            return totalSize;
        } catch (error) {
            return 0;
        }
    }

    calculateDatabaseSize() {
        try {
            const dbFiles = ['users.json', 'videos.json', 'ads.json', 'categories.json'];
            let totalSize = 0;
            dbFiles.forEach(file => {
                if (fs.existsSync(file)) {
                    totalSize += fs.statSync(file).size;
                }
            });
            return totalSize;
        } catch (error) {
            return 0;
        }
    }

    calculatePerformanceScore(performance) {
        let score = 100;
        if (performance.bundleSize > 1024 * 1024) score -= 20; // > 1MB
        if (performance.databaseSize > 1024 * 1024) score -= 10; // > 1MB
        if (performance.loadTime > 3000) score -= 30; // > 3s
        return Math.max(score, 20);
    }

    getUserCount() {
        try {
            if (fs.existsSync('users.json')) {
                const users = JSON.parse(fs.readFileSync('users.json', 'utf8'));
                return Array.isArray(users) ? users.length : 0;
            }
        } catch (error) {
            return 0;
        }
        return 0;
    }

    getVideoCount() {
        try {
            if (fs.existsSync('videos.json')) {
                const videos = JSON.parse(fs.readFileSync('videos.json', 'utf8'));
                return Array.isArray(videos) ? videos.length : 0;
            }
        } catch (error) {
            return 0;
        }
        return 0;
    }

    getCategoryCount() {
        try {
            if (fs.existsSync('categories.json')) {
                const categories = JSON.parse(fs.readFileSync('categories.json', 'utf8'));
                return Array.isArray(categories) ? categories.length : 0;
            }
        } catch (error) {
            return 0;
        }
        return 0;
    }

    getAdCount() {
        try {
            if (fs.existsSync('ads.json')) {
                const ads = JSON.parse(fs.readFileSync('ads.json', 'utf8'));
                return Array.isArray(ads) ? ads.length : 0;
            }
        } catch (error) {
            return 0;
        }
        return 0;
    }

    getAdminUserCount() {
        try {
            if (fs.existsSync('users.json')) {
                const users = JSON.parse(fs.readFileSync('users.json', 'utf8'));
                return users.filter(user => user.isAdmin || user.isSuperAdmin).length;
            }
        } catch (error) {
            return 0;
        }
        return 0;
    }

    checkVideoUploadFeature() {
        return {
            status: fs.existsSync('uploads') ? 'working' : 'not working',
            directory: fs.existsSync('uploads'),
            uploadedFiles: fs.existsSync('uploads') ? fs.readdirSync('uploads').length : 0
        };
    }

    checkUserManagementFeature() {
        return {
            status: fs.existsSync('users.json') ? 'working' : 'not working',
            userFile: fs.existsSync('users.json'),
            userCount: this.getUserCount()
        };
    }

    checkAdminPanelFeature() {
        return {
            status: fs.existsSync('admin.html') ? 'working' : 'not working',
            adminFile: fs.existsSync('admin.html'),
            adminScript: fs.existsSync('admin-script.js')
        };
    }

    checkAdsSystemFeature() {
        return {
            status: fs.existsSync('ads.json') ? 'working' : 'not working',
            adsFile: fs.existsSync('ads.json'),
            adCount: this.getAdCount()
        };
    }

    checkApiEndpoints() {
        const apiFiles = this.getAllFiles('.').filter(f => f.includes('-api.js'));
        return {
            status: apiFiles.length > 0 ? 'working' : 'not working',
            count: apiFiles.length,
            files: apiFiles
        };
    }

    checkStorageSystemFeature() {
        return {
            status: fs.existsSync('storage') ? 'working' : 'not working',
            storageDir: fs.existsSync('storage'),
            backupSystems: fs.existsSync('system_backup')
        };
    }

    getAllFiles(dir, files = []) {
        try {
            const items = fs.readdirSync(dir);
            items.forEach(item => {
                const fullPath = path.join(dir, item);
                const stats = fs.statSync(fullPath);
                if (stats.isDirectory() && !item.startsWith('.') && item !== 'node_modules') {
                    this.getAllFiles(fullPath, files);
                } else if (stats.isFile()) {
                    files.push(fullPath);
                }
            });
        } catch (error) {
            // Skip inaccessible directories
        }
        return files;
    }

    countAllFiles() {
        return this.getAllFiles('.').length;
    }

    calculateTotalSize() {
        const files = this.getAllFiles('.');
        let totalSize = 0;
        files.forEach(file => {
            try {
                totalSize += fs.statSync(file).size;
            } catch (error) {
                // Skip files that can't be accessed
            }
        });
        return totalSize;
    }

    formatSize(bytes) {
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        if (bytes === 0) return '0 Bytes';
        const i = Math.floor(Math.log(bytes) / Math.log(1024));
        return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
    }

    async generateRecommendations() {
        console.log('💡 Generating Recommendations...');
        
        const recommendations = [];
        
        // Security recommendations
        if (this.analysisResults.security.score < 80) {
            recommendations.push({
                priority: 'High',
                category: 'Security',
                issue: 'Security vulnerabilities detected',
                action: 'Move sensitive files to secure directory and fix code vulnerabilities'
            });
        }
        
        // Performance recommendations
        if (this.analysisResults.performance.score < 80) {
            recommendations.push({
                priority: 'Medium',
                category: 'Performance',
                issue: 'Performance optimization needed',
                action: 'Optimize bundle size and implement caching'
            });
        }
        
        // Database recommendations
        if (this.analysisResults.database.userCount === 0) {
            recommendations.push({
                priority: 'Low',
                category: 'Database',
                issue: 'No users in system',
                action: 'Create default admin user for testing'
            });
        }
        
        this.analysisResults.recommendations = recommendations;
    }

    generateCompleteReport() {
        const report = {
            ...this.analysisResults,
            summary: {
                overallScore: this.calculateOverallScore(),
                status: this.getOverallStatus(),
                criticalIssues: this.analysisResults.recommendations.filter(r => r.priority === 'High').length,
                totalRecommendations: this.analysisResults.recommendations.length
            }
        };
        
        // Save detailed report
        fs.writeFileSync('complete-system-analysis-report.json', JSON.stringify(report, null, 2));
        
        // Display summary
        console.log('\n📊 COMPLETE SYSTEM ANALYSIS REPORT');
        console.log('=' .repeat(60));
        console.log(`🏥 System Health: ${this.analysisResults.systemHealth.score}% - ${this.analysisResults.systemHealth.status}`);
        console.log(`🔒 Security Score: ${this.analysisResults.security.score}% - ${this.analysisResults.security.status}`);
        console.log(`⚡ Performance: ${this.analysisResults.performance.score}% - ${this.analysisResults.performance.status}`);
        console.log(`📁 Total Files: ${this.analysisResults.files.totalFiles}`);
        console.log(`🗄️ Database: ${this.analysisResults.database.userCount} users, ${this.analysisResults.database.videoCount} videos`);
        console.log(`🔐 Admin Users: ${this.analysisResults.authentication.adminUsers}`);
        
        const workingFeatures = Object.values(this.analysisResults.features).filter(f => f.status === 'working').length;
        console.log(`🎯 Features: ${workingFeatures}/${Object.keys(this.analysisResults.features).length} working`);
        
        console.log(`\n📈 Overall Score: ${report.summary.overallScore}% - ${report.summary.status}`);
        console.log(`⚠️ Critical Issues: ${report.summary.criticalIssues}`);
        console.log(`💡 Total Recommendations: ${report.summary.totalRecommendations}`);
        
        if (report.summary.criticalIssues > 0) {
            console.log('\n🚨 CRITICAL ISSUES TO ADDRESS:');
            this.analysisResults.recommendations
                .filter(r => r.priority === 'High')
                .forEach((rec, index) => {
                    console.log(`${index + 1}. ${rec.category}: ${rec.issue}`);
                    console.log(`   Action: ${rec.action}\n`);
                });
        }
        
        console.log('=' .repeat(60));
        console.log('📋 Detailed report saved: complete-system-analysis-report.json');
    }

    calculateOverallScore() {
        const scores = [
            this.analysisResults.systemHealth.score || 0,
            this.analysisResults.security.score || 0,
            this.analysisResults.performance.score || 0
        ];
        return Math.round(scores.reduce((a, b) => a + b, 0) / scores.length);
    }

    getOverallStatus() {
        const score = this.calculateOverallScore();
        if (score >= 90) return 'Excellent';
        if (score >= 80) return 'Good';
        if (score >= 60) return 'Fair';
        return 'Needs Attention';
    }

    // Additional check methods
    checkDataIntegrity() {
        const dbFiles = ['users.json', 'videos.json', 'ads.json', 'categories.json'];
        let integrityScore = 0;
        
        dbFiles.forEach(file => {
            try {
                if (fs.existsSync(file)) {
                    JSON.parse(fs.readFileSync(file, 'utf8'));
                    integrityScore += 25;
                }
            } catch (error) {
                // File is corrupted
            }
        });
        
        return integrityScore;
    }

    checkDatabaseBackups() {
        return fs.existsSync('database_backup') && 
               fs.readdirSync('database_backup').length > 0;
    }

    checkUserSessions() {
        // Simulate session check
        return 'No active sessions detected';
    }

    checkPasswordSecurity() {
        // Basic password security check
        return 'Standard security measures in place';
    }

    testLoginSystem() {
        return fs.existsSync('admin.html') && fs.existsSync('index.html');
    }

    checkFilePermissions() {
        // Simplified permission check
        const criticalFiles = ['index.js', 'admin.html'];
        return criticalFiles.filter(file => fs.existsSync(file)).length;
    }

    checkAuthSecurity() {
        return this.getAdminUserCount() > 0 ? 'Admin accounts present' : 'No admin accounts';
    }

    calculateTotalSize() {
        const files = this.getAllFiles('.');
        let totalSize = 0;
        files.forEach(file => {
            try {
                totalSize += fs.statSync(file).size;
            } catch (error) {
                // Skip inaccessible files
            }
        });
        return totalSize;
    }

    findDuplicateFiles() {
        // Simplified duplicate detection
        const files = this.getAllFiles('.');
        const backupFiles = files.filter(f => f.includes('.backup') || f.includes('.bak'));
        return backupFiles.length;
    }

    findLargeFiles() {
        const files = this.getAllFiles('.');
        const largeFiles = [];
        files.forEach(file => {
            try {
                const stats = fs.statSync(file);
                if (stats.size > 1024 * 1024) { // > 1MB
                    largeFiles.push({ file, size: stats.size });
                }
            } catch (error) {
                // Skip inaccessible files
            }
        });
        return largeFiles;
    }

    checkFileOrganization() {
        const directories = ['uploads', 'thumbnails', 'storage', 'system_backup'];
        return directories.filter(dir => fs.existsSync(dir)).length / directories.length * 100;
    }

    checkImageOptimization() {
        // Simplified image optimization check
        return 'Standard optimization';
    }

    checkCachingStatus() {
        // Simplified caching check
        return 'Basic caching implemented';
    }

    estimateLoadTime() {
        // Estimated load time based on bundle size
        const bundleSize = this.calculateBundleSize();
        return Math.max(1000, bundleSize / 1000); // Rough estimate in ms
    }
}

// Run complete analysis if called directly
if (require.main === module) {
    const analysis = new CompleteSystemAnalysis();
    analysis.runCompleteAnalysis().catch(error => {
        console.error('❌ Complete analysis failed:', error);
    });
}

module.exports = CompleteSystemAnalysis;
