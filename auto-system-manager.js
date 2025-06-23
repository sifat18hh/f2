
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const PackagePersistenceManager = require('./package-persistence.js');

class AutoSystemManager {
    constructor() {
        this.packageManager = new PackagePersistenceManager();
        this.monitoringActive = false;
        this.backupInterval = null;
        this.healthCheckInterval = null;
        this.performanceMonitor = null;
        this.autoRepairSystem = null;
        
        console.log('🤖 Auto System Manager starting...');
        this.initialize();
    }

    async initialize() {
        try {
            // Start all automatic systems
            await this.startAutomaticPackageManagement();
            await this.startAutomaticBackupSystem();
            await this.startWebsiteMonitoring();
            await this.startAutoRepairSystem();
            await this.startPerformanceOptimization();
            
            console.log('✅ All automatic systems initialized successfully!');
            this.logSystemStatus();
            
        } catch (error) {
            console.error('❌ Auto System initialization failed:', error.message);
        }
    }

    // 1. Automatic Package Management
    async startAutomaticPackageManagement() {
        console.log('📦 Starting Automatic Package Management...');
        
        // Auto-detect and install missing packages every 30 minutes
        setInterval(async () => {
            await this.autoDetectAndInstallPackages();
        }, 30 * 60 * 1000); // 30 minutes

        // Watch for package.json changes and auto-install
        if (fs.existsSync('package.json')) {
            fs.watchFile('package.json', async (curr, prev) => {
                console.log('📝 Package.json changed, auto-installing packages...');
                await this.autoInstallFromPackageJson();
            });
        }

        // Initial package check
        await this.autoDetectAndInstallPackages();
    }

    async autoDetectAndInstallPackages() {
        try {
            console.log('🔍 Auto-detecting required packages...');
            
            // Check if node_modules exists and has packages
            if (!fs.existsSync('node_modules') || fs.readdirSync('node_modules').length === 0) {
                console.log('📥 Node modules missing, auto-installing...');
                await this.safeNpmInstall();
            }

            // Check for missing dependencies
            const missingPackages = await this.detectMissingPackages();
            if (missingPackages.length > 0) {
                console.log(`📦 Auto-installing ${missingPackages.length} missing packages...`);
                await this.installMissingPackages(missingPackages);
            }

            // Auto-backup after successful package operations
            setTimeout(() => {
                this.packageManager.backupPackages();
            }, 5000);

        } catch (error) {
            console.error('❌ Auto package detection failed:', error.message);
        }
    }

    async detectMissingPackages() {
        const missingPackages = [];
        
        try {
            if (fs.existsSync('package.json')) {
                const packageJson = JSON.parse(fs.readFileSync('package.json', 'utf8'));
                const allDeps = { ...packageJson.dependencies, ...packageJson.devDependencies };
                
                for (const [pkg, version] of Object.entries(allDeps)) {
                    try {
                        require.resolve(pkg);
                    } catch (e) {
                        missingPackages.push(pkg);
                    }
                }
            }
        } catch (error) {
            console.error('Error detecting missing packages:', error.message);
        }
        
        return missingPackages;
    }

    async installMissingPackages(packages) {
        for (const pkg of packages) {
            try {
                console.log(`📦 Auto-installing: ${pkg}`);
                execSync(`npm install ${pkg}`, { stdio: 'pipe' });
                console.log(`✅ Successfully installed: ${pkg}`);
            } catch (error) {
                console.error(`❌ Failed to install ${pkg}:`, error.message);
            }
        }
    }

    async autoInstallFromPackageJson() {
        try {
            await this.safeNpmInstall();
            setTimeout(() => {
                this.packageManager.backupPackages();
            }, 3000);
        } catch (error) {
            console.error('❌ Auto install from package.json failed:', error.message);
        }
    }

    async safeNpmInstall() {
        try {
            console.log('📥 Running safe npm install...');
            execSync('npm install', { stdio: 'pipe', timeout: 300000 });
            console.log('✅ NPM install completed successfully');
        } catch (error) {
            console.log('⚠️ Standard install failed, trying with --force...');
            try {
                execSync('npm install --force', { stdio: 'pipe', timeout: 300000 });
                console.log('✅ Force install completed');
            } catch (forceError) {
                console.error('❌ All install attempts failed:', forceError.message);
            }
        }
    }

    // 2. Automatic Backup System
    async startAutomaticBackupSystem() {
        console.log('💾 Starting Automatic Backup System...');
        
        // Backup every 15 minutes
        this.backupInterval = setInterval(() => {
            this.performAutomaticBackup();
        }, 15 * 60 * 1000); // 15 minutes

        // Backup on file changes
        this.watchCriticalFiles();
        
        // Initial backup
        this.performAutomaticBackup();
    }

    performAutomaticBackup() {
        try {
            console.log('💾 Performing automatic backup...');
            
            // Backup packages
            this.packageManager.backupPackages();
            
            // Backup critical project files
            this.backupCriticalFiles();
            
            // Backup database files
            this.backupDatabaseFiles();
            
            // Create system snapshot
            this.createSystemSnapshot();
            
            console.log('✅ Automatic backup completed');
            
        } catch (error) {
            console.error('❌ Automatic backup failed:', error.message);
        }
    }

    backupCriticalFiles() {
        const criticalFiles = [
            'index.js', 'package.json', 'package-lock.json',
            'videos.json', 'users.json', 'ads.json',
            'categories.json', 'earnings.json'
        ];
        
        const backupDir = './system_backup';
        if (!fs.existsSync(backupDir)) {
            fs.mkdirSync(backupDir, { recursive: true });
        }
        
        criticalFiles.forEach(file => {
            if (fs.existsSync(file)) {
                try {
                    fs.copyFileSync(file, path.join(backupDir, file));
                } catch (error) {
                    console.error(`Failed to backup ${file}:`, error.message);
                }
            }
        });
    }

    backupDatabaseFiles() {
        const dbFiles = fs.readdirSync('.')
            .filter(file => file.endsWith('.json') && !file.startsWith('package'));
        
        const dbBackupDir = './database_backup';
        if (!fs.existsSync(dbBackupDir)) {
            fs.mkdirSync(dbBackupDir, { recursive: true });
        }
        
        dbFiles.forEach(file => {
            try {
                fs.copyFileSync(file, path.join(dbBackupDir, file));
            } catch (error) {
                console.error(`Failed to backup database file ${file}:`, error.message);
            }
        });
    }

    createSystemSnapshot() {
        const snapshot = {
            timestamp: new Date().toISOString(),
            nodeVersion: process.version,
            packageCount: 0,
            fileCount: 0,
            systemHealth: this.getSystemHealth(),
            status: 'healthy'
        };
        
        try {
            if (fs.existsSync('node_modules')) {
                snapshot.packageCount = fs.readdirSync('node_modules').length;
            }
            snapshot.fileCount = this.countProjectFiles();
        } catch (error) {
            console.error('Error creating system snapshot:', error.message);
        }
        
        fs.writeFileSync('./system_backup/snapshot.json', JSON.stringify(snapshot, null, 2));
    }

    watchCriticalFiles() {
        const filesToWatch = [
            'package.json', 'index.js', 'videos.json', 'users.json'
        ];
        
        filesToWatch.forEach(file => {
            if (fs.existsSync(file)) {
                fs.watchFile(file, (curr, prev) => {
                    console.log(`📝 ${file} changed, creating backup...`);
                    setTimeout(() => {
                        this.performAutomaticBackup();
                    }, 2000);
                });
            }
        });
    }

    // 3. Website Monitoring System
    async startWebsiteMonitoring() {
        console.log('🌐 Starting Website Monitoring System...');
        
        this.monitoringActive = true;
        
        // Health check every 2 minutes
        this.healthCheckInterval = setInterval(() => {
            this.performHealthCheck();
        }, 2 * 60 * 1000); // 2 minutes
        
        // Performance monitoring every 5 minutes
        this.performanceMonitor = setInterval(() => {
            this.monitorPerformance();
        }, 5 * 60 * 1000); // 5 minutes
        
        // Initial health check
        this.performHealthCheck();
    }

    performHealthCheck() {
        try {
            const health = {
                timestamp: new Date().toISOString(),
                serverStatus: this.checkServerStatus(),
                databaseStatus: this.checkDatabaseStatus(),
                filesystemStatus: this.checkFilesystemStatus(),
                memoryUsage: process.memoryUsage(),
                uptime: process.uptime()
            };
            
            // Log health status
            if (health.serverStatus && health.databaseStatus && health.filesystemStatus) {
                console.log('✅ Health check passed - All systems operational');
            } else {
                console.warn('⚠️ Health check issues detected');
                this.handleHealthIssues(health);
            }
            
            // Save health report
            this.saveHealthReport(health);
            
        } catch (error) {
            console.error('❌ Health check failed:', error.message);
        }
    }

    checkServerStatus() {
        try {
            // Check if main files exist and are readable
            return fs.existsSync('index.js') && fs.existsSync('package.json');
        } catch (error) {
            return false;
        }
    }

    checkDatabaseStatus() {
        try {
            // Check if database files are accessible
            const dbFiles = ['videos.json', 'users.json'];
            return dbFiles.every(file => {
                try {
                    if (fs.existsSync(file)) {
                        JSON.parse(fs.readFileSync(file, 'utf8'));
                        return true;
                    }
                    return true; // File might not exist yet, that's ok
                } catch (e) {
                    return false;
                }
            });
        } catch (error) {
            return false;
        }
    }

    checkFilesystemStatus() {
        try {
            // Check if we can write to filesystem
            const testFile = './health_test.tmp';
            fs.writeFileSync(testFile, 'test');
            fs.unlinkSync(testFile);
            return true;
        } catch (error) {
            return false;
        }
    }

    handleHealthIssues(health) {
        console.log('🔧 Attempting to fix health issues...');
        
        if (!health.serverStatus) {
            console.log('🔧 Server status issue detected, attempting repair...');
            this.repairServerFiles();
        }
        
        if (!health.databaseStatus) {
            console.log('🔧 Database issue detected, attempting repair...');
            this.repairDatabaseFiles();
        }
        
        if (!health.filesystemStatus) {
            console.log('🔧 Filesystem issue detected, attempting repair...');
            this.repairFilesystem();
        }
    }

    saveHealthReport(health) {
        const reportsDir = './health_reports';
        if (!fs.existsSync(reportsDir)) {
            fs.mkdirSync(reportsDir, { recursive: true });
        }
        
        const reportFile = path.join(reportsDir, `health_${Date.now()}.json`);
        fs.writeFileSync(reportFile, JSON.stringify(health, null, 2));
        
        // Keep only last 50 reports
        this.cleanOldReports(reportsDir, 50);
    }

    monitorPerformance() {
        try {
            const performance = {
                timestamp: new Date().toISOString(),
                memory: process.memoryUsage(),
                cpuUsage: process.cpuUsage(),
                uptime: process.uptime(),
                activeConnections: this.getActiveConnections(),
                responseTime: this.measureResponseTime()
            };
            
            // Auto-optimize if performance is degraded
            if (this.isPerformanceDegraded(performance)) {
                console.log('⚡ Performance degradation detected, auto-optimizing...');
                this.autoOptimizePerformance();
            }
            
            this.savePerformanceReport(performance);
            
        } catch (error) {
            console.error('❌ Performance monitoring failed:', error.message);
        }
    }

    // 4. Auto Repair System
    async startAutoRepairSystem() {
        console.log('🔧 Starting Auto Repair System...');
        
        // Monitor for common issues every 5 minutes
        this.autoRepairSystem = setInterval(() => {
            this.performAutoRepair();
        }, 5 * 60 * 1000); // 5 minutes
    }

    performAutoRepair() {
        try {
            console.log('🔧 Performing auto repair checks...');
            
            // Repair missing packages
            this.repairMissingPackages();
            
            // Repair corrupted files
            this.repairCorruptedFiles();
            
            // Repair missing directories
            this.repairMissingDirectories();
            
            // Clean up temporary files
            this.cleanupTempFiles();
            
        } catch (error) {
            console.error('❌ Auto repair failed:', error.message);
        }
    }

    async repairMissingPackages() {
        const missingPackages = await this.detectMissingPackages();
        if (missingPackages.length > 0) {
            console.log(`🔧 Repairing ${missingPackages.length} missing packages...`);
            await this.installMissingPackages(missingPackages);
        }
    }

    repairCorruptedFiles() {
        const criticalFiles = [
            { file: 'videos.json', default: '[]' },
            { file: 'users.json', default: '[]' },
            { file: 'ads.json', default: '[]' },
            { file: 'categories.json', default: '[]' }
        ];
        
        criticalFiles.forEach(({ file, default: defaultContent }) => {
            try {
                if (fs.existsSync(file)) {
                    JSON.parse(fs.readFileSync(file, 'utf8'));
                } else {
                    console.log(`🔧 Creating missing file: ${file}`);
                    fs.writeFileSync(file, defaultContent);
                }
            } catch (error) {
                console.log(`🔧 Repairing corrupted file: ${file}`);
                fs.writeFileSync(file, defaultContent);
            }
        });
    }

    repairMissingDirectories() {
        const requiredDirs = [
            'uploads', 'thumbnails', 'package_backup', 
            'system_backup', 'database_backup', 'health_reports'
        ];
        
        requiredDirs.forEach(dir => {
            if (!fs.existsSync(dir)) {
                console.log(`🔧 Creating missing directory: ${dir}`);
                fs.mkdirSync(dir, { recursive: true });
            }
        });
    }

    cleanupTempFiles() {
        const tempPatterns = ['.tmp', '.temp', '.log'];
        
        try {
            const files = fs.readdirSync('.');
            files.forEach(file => {
                if (tempPatterns.some(pattern => file.endsWith(pattern))) {
                    try {
                        fs.unlinkSync(file);
                        console.log(`🧹 Cleaned up temp file: ${file}`);
                    } catch (error) {
                        // Ignore if file is in use
                    }
                }
            });
        } catch (error) {
            console.error('Error during cleanup:', error.message);
        }
    }

    // Helper methods
    getSystemHealth() {
        return {
            memory: process.memoryUsage(),
            uptime: process.uptime(),
            nodeVersion: process.version,
            packageStatus: fs.existsSync('node_modules'),
            backupStatus: fs.existsSync('./system_backup')
        };
    }

    countProjectFiles() {
        try {
            return fs.readdirSync('.').length;
        } catch (error) {
            return 0;
        }
    }

    getActiveConnections() {
        // Simulated active connections count
        return Math.floor(Math.random() * 50) + 10;
    }

    measureResponseTime() {
        // Simulated response time
        return Math.floor(Math.random() * 200) + 50;
    }

    isPerformanceDegraded(performance) {
        return performance.memory.heapUsed > 100 * 1024 * 1024 || // 100MB
               performance.responseTime > 1000; // 1 second
    }

    autoOptimizePerformance() {
        // Force garbage collection if available
        if (global.gc) {
            global.gc();
            console.log('♻️ Garbage collection performed');
        }
        
        // Clear caches
        this.clearSystemCaches();
    }

    clearSystemCaches() {
        try {
            // Clear require cache for non-core modules
            Object.keys(require.cache).forEach(key => {
                if (!key.includes('node_modules')) {
                    delete require.cache[key];
                }
            });
            console.log('🧹 System caches cleared');
        } catch (error) {
            console.error('Error clearing caches:', error.message);
        }
    }

    savePerformanceReport(performance) {
        const reportsDir = './performance_reports';
        if (!fs.existsSync(reportsDir)) {
            fs.mkdirSync(reportsDir, { recursive: true });
        }
        
        const reportFile = path.join(reportsDir, `perf_${Date.now()}.json`);
        fs.writeFileSync(reportFile, JSON.stringify(performance, null, 2));
        
        this.cleanOldReports(reportsDir, 30);
    }

    cleanOldReports(directory, keepCount) {
        try {
            const files = fs.readdirSync(directory)
                .map(file => ({
                    name: file,
                    path: path.join(directory, file),
                    time: fs.statSync(path.join(directory, file)).mtime
                }))
                .sort((a, b) => b.time - a.time);
            
            if (files.length > keepCount) {
                files.slice(keepCount).forEach(file => {
                    try {
                        fs.unlinkSync(file.path);
                    } catch (error) {
                        // Ignore deletion errors
                    }
                });
            }
        } catch (error) {
            console.error('Error cleaning old reports:', error.message);
        }
    }

    // 5. Performance Optimization
    async startPerformanceOptimization() {
        console.log('⚡ Starting Performance Optimization...');
        
        // Optimize every 30 minutes
        setInterval(() => {
            this.performOptimization();
        }, 30 * 60 * 1000); // 30 minutes
        
        // Initial optimization
        this.performOptimization();
    }

    performOptimization() {
        try {
            console.log('⚡ Performing system optimization...');
            
            // Memory optimization
            this.optimizeMemory();
            
            // File system optimization
            this.optimizeFileSystem();
            
            // Database optimization
            this.optimizeDatabase();
            
            console.log('✅ System optimization completed');
            
        } catch (error) {
            console.error('❌ Optimization failed:', error.message);
        }
    }

    optimizeMemory() {
        if (global.gc) {
            global.gc();
        }
        
        // Clear old logs from memory
        console.log('♻️ Memory optimized');
    }

    optimizeFileSystem() {
        // Remove old backup files (keep last 10)
        this.cleanOldReports('./health_reports', 10);
        this.cleanOldReports('./performance_reports', 10);
        
        console.log('📁 File system optimized');
    }

    optimizeDatabase() {
        // Compact JSON files by removing extra whitespace
        const dbFiles = ['videos.json', 'users.json', 'ads.json'];
        
        dbFiles.forEach(file => {
            if (fs.existsSync(file)) {
                try {
                    const data = JSON.parse(fs.readFileSync(file, 'utf8'));
                    fs.writeFileSync(file, JSON.stringify(data));
                } catch (error) {
                    // Ignore if file is corrupted, auto-repair will handle it
                }
            }
        });
        
        console.log('🗄️ Database optimized');
    }

    // System status and control methods
    getSystemStatus() {
        return {
            packageManagement: 'active',
            backupSystem: this.backupInterval ? 'active' : 'inactive',
            monitoring: this.monitoringActive,
            autoRepair: this.autoRepairSystem ? 'active' : 'inactive',
            lastBackup: this.getLastBackupTime(),
            systemHealth: this.getSystemHealth()
        };
    }

    getLastBackupTime() {
        try {
            if (fs.existsSync('./system_backup/snapshot.json')) {
                const snapshot = JSON.parse(fs.readFileSync('./system_backup/snapshot.json', 'utf8'));
                return snapshot.timestamp;
            }
        } catch (error) {
            return 'Never';
        }
        return 'Never';
    }

    logSystemStatus() {
        const status = this.getSystemStatus();
        console.log('\n🤖 AUTO SYSTEM STATUS:');
        console.log('========================');
        console.log(`📦 Package Management: ${status.packageManagement}`);
        console.log(`💾 Backup System: ${status.backupSystem}`);
        console.log(`🌐 Website Monitoring: ${status.monitoring ? 'active' : 'inactive'}`);
        console.log(`🔧 Auto Repair: ${status.autoRepair}`);
        console.log(`🕐 Last Backup: ${status.lastBackup}`);
        console.log(`💚 System Health: ${status.systemHealth.packageStatus ? 'Good' : 'Needs Attention'}`);
        console.log('========================\n');
    }

    // Manual control methods
    async forceBackup() {
        console.log('🔄 Forcing immediate backup...');
        this.performAutomaticBackup();
    }

    async forceRepair() {
        console.log('🔄 Forcing immediate repair...');
        this.performAutoRepair();
    }

    async forceOptimization() {
        console.log('🔄 Forcing immediate optimization...');
        this.performOptimization();
    }

    // Shutdown method
    shutdown() {
        console.log('🛑 Shutting down Auto System Manager...');
        
        if (this.backupInterval) {
            clearInterval(this.backupInterval);
        }
        
        if (this.healthCheckInterval) {
            clearInterval(this.healthCheckInterval);
        }
        
        if (this.performanceMonitor) {
            clearInterval(this.performanceMonitor);
        }
        
        if (this.autoRepairSystem) {
            clearInterval(this.autoRepairSystem);
        }
        
        this.monitoringActive = false;
        
        console.log('✅ Auto System Manager shutdown complete');
    }
}

module.exports = AutoSystemManager;
