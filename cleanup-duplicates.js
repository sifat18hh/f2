
const fs = require('fs');
const path = require('path');

class ProjectCleanup {
    constructor() {
        this.duplicatesToRemove = [
            // Backup files that are duplicates
            'check-super-ai.js.backup',
            'database_backup/admin-credentials.json',
            'database_backup/ads.json',
            'database_backup/ai-content-suggestions.json',
            // Add more duplicates as needed
        ];
        
        this.sensitiveFiles = [
            'admin-credentials.json',
            'deploy.config.json',
            'engagement-config.json'
        ];
    }

    async cleanup() {
        console.log('🧹 Starting project cleanup...');
        
        // Remove duplicate files
        this.removeDuplicates();
        
        // Secure sensitive files
        this.secureSensitiveFiles();
        
        // Create summary
        this.createCleanupReport();
        
        console.log('✅ Cleanup completed!');
    }

    removeDuplicates() {
        console.log('🗑️ Removing duplicate files...');
        
        this.duplicatesToRemove.forEach(file => {
            if (fs.existsSync(file)) {
                try {
                    fs.unlinkSync(file);
                    console.log(`   ✅ Removed: ${file}`);
                } catch (error) {
                    console.log(`   ❌ Failed to remove: ${file}`);
                }
            }
        });
    }

    secureSensitiveFiles() {
        console.log('🔒 Securing sensitive files...');
        
        // Move sensitive files to secure location
        const secureDir = './secure_config';
        if (!fs.existsSync(secureDir)) {
            fs.mkdirSync(secureDir, { recursive: true });
        }
        
        this.sensitiveFiles.forEach(file => {
            if (fs.existsSync(file)) {
                try {
                    const newPath = path.join(secureDir, file);
                    fs.renameSync(file, newPath);
                    console.log(`   🔒 Secured: ${file} → ${newPath}`);
                } catch (error) {
                    console.log(`   ❌ Failed to secure: ${file}`);
                }
            }
        });
    }

    createCleanupReport() {
        const report = {
            timestamp: new Date().toISOString(),
            duplicatesRemoved: this.duplicatesToRemove.length,
            sensitiveFilesSecured: this.sensitiveFiles.length,
            recommendations: [
                'Use environment variables for sensitive data',
                'Implement proper .gitignore for config files',
                'Regular cleanup of duplicate files',
                'Code review for security patterns'
            ]
        };
        
        fs.writeFileSync('cleanup-report.json', JSON.stringify(report, null, 2));
        console.log('📋 Cleanup report saved: cleanup-report.json');
    }
}

// Run cleanup
if (require.main === module) {
    const cleanup = new ProjectCleanup();
    cleanup.cleanup();
}

module.exports = ProjectCleanup;
