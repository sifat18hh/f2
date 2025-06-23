
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

class WebsiteFileScanner {
    constructor() {
        this.scanResults = {
            totalFiles: 0,
            totalSize: 0,
            fileTypes: {},
            errors: [],
            warnings: [],
            securityIssues: [],
            duplicates: [],
            largeFiles: [],
            emptyFiles: [],
            scanDate: new Date(),
            directories: []
        };
        this.fileHashes = new Map();
        this.excludePatterns = [
            'node_modules',
            '.git',
            'package-lock.json',
            '.DS_Store',
            'Thumbs.db'
        ];
    }

    async scanAllFiles() {
        console.log('🔍 Starting comprehensive website file scan...');
        console.log('=' * 60);
        
        try {
            await this.scanDirectory('.');
            await this.analyzeScanResults();
            await this.generateReport();
            this.printScanSummary();
            
        } catch (error) {
            console.error('❌ Scan error:', error.message);
        }
    }

    async scanDirectory(dirPath) {
        try {
            const items = fs.readdirSync(dirPath);
            
            for (const item of items) {
                const fullPath = path.join(dirPath, item);
                
                // Skip excluded patterns
                if (this.shouldExclude(item)) {
                    continue;
                }
                
                const stats = fs.statSync(fullPath);
                
                if (stats.isDirectory()) {
                    this.scanResults.directories.push({
                        path: fullPath,
                        size: this.getDirectorySize(fullPath),
                        fileCount: this.getDirectoryFileCount(fullPath)
                    });
                    
                    // Recursively scan subdirectory
                    await this.scanDirectory(fullPath);
                    
                } else if (stats.isFile()) {
                    await this.scanFile(fullPath, stats);
                }
            }
        } catch (error) {
            this.scanResults.errors.push({
                type: 'Directory Access Error',
                path: dirPath,
                message: error.message
            });
        }
    }

    async scanFile(filePath, stats) {
        try {
            this.scanResults.totalFiles++;
            this.scanResults.totalSize += stats.size;
            
            const ext = path.extname(filePath).toLowerCase();
            const fileType = this.getFileType(ext);
            
            // Count file types
            if (!this.scanResults.fileTypes[fileType]) {
                this.scanResults.fileTypes[fileType] = { count: 0, size: 0 };
            }
            this.scanResults.fileTypes[fileType].count++;
            this.scanResults.fileTypes[fileType].size += stats.size;
            
            // Check file size
            if (stats.size > 10 * 1024 * 1024) { // > 10MB
                this.scanResults.largeFiles.push({
                    path: filePath,
                    size: this.formatBytes(stats.size),
                    type: fileType
                });
            }
            
            // Check empty files
            if (stats.size === 0) {
                this.scanResults.emptyFiles.push(filePath);
            }
            
            // Check for duplicates
            if (stats.size < 100 * 1024 * 1024) { // Only hash files < 100MB
                const hash = await this.getFileHash(filePath);
                if (this.fileHashes.has(hash)) {
                    this.scanResults.duplicates.push({
                        original: this.fileHashes.get(hash),
                        duplicate: filePath,
                        size: this.formatBytes(stats.size)
                    });
                } else {
                    this.fileHashes.set(hash, filePath);
                }
            }
            
            // Security checks
            await this.performSecurityCheck(filePath, ext);
            
            // Content validation
            await this.validateFileContent(filePath, ext);
            
            console.log(`✅ Scanned: ${filePath} (${this.formatBytes(stats.size)})`);
            
        } catch (error) {
            this.scanResults.errors.push({
                type: 'File Scan Error',
                path: filePath,
                message: error.message
            });
        }
    }

    async getFileHash(filePath) {
        return new Promise((resolve, reject) => {
            const hash = crypto.createHash('md5');
            const stream = fs.createReadStream(filePath);
            
            stream.on('data', data => hash.update(data));
            stream.on('end', () => resolve(hash.digest('hex')));
            stream.on('error', reject);
        });
    }

    async performSecurityCheck(filePath, ext) {
        try {
            // Check for sensitive files
            const fileName = path.basename(filePath).toLowerCase();
            const sensitivePatterns = [
                'password', 'secret', 'key', 'token', 'credential',
                '.env', 'config.json', 'database.json'
            ];
            
            if (sensitivePatterns.some(pattern => fileName.includes(pattern))) {
                this.scanResults.securityIssues.push({
                    type: 'Sensitive File',
                    path: filePath,
                    risk: 'High',
                    description: 'File may contain sensitive information'
                });
            }
            
            // Check executable files
            if (['.js', '.exe', '.bat', '.sh'].includes(ext)) {
                const content = fs.readFileSync(filePath, 'utf8');
                
                // Check for suspicious patterns
                const suspiciousPatterns = [
                    'eval\\s*\\(', 'exec\\s*\\(', 'system\\s*\\(',
                    'rm\\s+-rf', 'del\\s+/s', 'format\\s+c:'
                ];
                
                for (const pattern of suspiciousPatterns) {
                    if (new RegExp(pattern, 'i').test(content)) {
                        this.scanResults.securityIssues.push({
                            type: 'Suspicious Code',
                            path: filePath,
                            risk: 'Medium',
                            pattern: pattern,
                            description: 'File contains potentially dangerous code'
                        });
                    }
                }
            }
            
        } catch (error) {
            // Ignore read errors for binary files
        }
    }

    async validateFileContent(filePath, ext) {
        try {
            if (ext === '.json') {
                const content = fs.readFileSync(filePath, 'utf8');
                JSON.parse(content);
            } else if (ext === '.js') {
                const content = fs.readFileSync(filePath, 'utf8');
                // Basic syntax check
                if (content.includes('undefined') && content.includes('error')) {
                    this.scanResults.warnings.push({
                        type: 'Potential JavaScript Error',
                        path: filePath,
                        description: 'File may contain error handling issues'
                    });
                }
            }
        } catch (error) {
            this.scanResults.errors.push({
                type: 'Content Validation Error',
                path: filePath,
                message: error.message
            });
        }
    }

    shouldExclude(itemName) {
        return this.excludePatterns.some(pattern => 
            itemName.includes(pattern) || itemName.startsWith('.')
        );
    }

    getFileType(ext) {
        const typeMap = {
            '.js': 'JavaScript',
            '.html': 'HTML',
            '.css': 'CSS',
            '.json': 'JSON',
            '.md': 'Markdown',
            '.txt': 'Text',
            '.png': 'Image',
            '.jpg': 'Image',
            '.jpeg': 'Image',
            '.gif': 'Image',
            '.mp4': 'Video',
            '.pdf': 'Document',
            '.zip': 'Archive'
        };
        
        return typeMap[ext] || 'Other';
    }

    getDirectorySize(dirPath) {
        try {
            let totalSize = 0;
            const items = fs.readdirSync(dirPath);
            
            for (const item of items) {
                if (this.shouldExclude(item)) continue;
                
                const fullPath = path.join(dirPath, item);
                const stats = fs.statSync(fullPath);
                
                if (stats.isDirectory()) {
                    totalSize += this.getDirectorySize(fullPath);
                } else {
                    totalSize += stats.size;
                }
            }
            
            return totalSize;
        } catch {
            return 0;
        }
    }

    getDirectoryFileCount(dirPath) {
        try {
            let count = 0;
            const items = fs.readdirSync(dirPath);
            
            for (const item of items) {
                if (this.shouldExclude(item)) continue;
                
                const fullPath = path.join(dirPath, item);
                const stats = fs.statSync(fullPath);
                
                if (stats.isDirectory()) {
                    count += this.getDirectoryFileCount(fullPath);
                } else {
                    count++;
                }
            }
            
            return count;
        } catch {
            return 0;
        }
    }

    async analyzeScanResults() {
        // Calculate percentages and insights
        this.scanResults.insights = {
            mostCommonFileType: this.getMostCommonFileType(),
            averageFileSize: this.scanResults.totalSize / this.scanResults.totalFiles,
            largestDirectory: this.getLargestDirectory(),
            duplicateCount: this.scanResults.duplicates.length,
            securityScore: this.calculateSecurityScore()
        };
    }

    getMostCommonFileType() {
        let maxCount = 0;
        let mostCommon = 'None';
        
        for (const [type, data] of Object.entries(this.scanResults.fileTypes)) {
            if (data.count > maxCount) {
                maxCount = data.count;
                mostCommon = type;
            }
        }
        
        return { type: mostCommon, count: maxCount };
    }

    getLargestDirectory() {
        return this.scanResults.directories.reduce((largest, dir) => 
            dir.size > (largest?.size || 0) ? dir : largest, null
        );
    }

    calculateSecurityScore() {
        const totalIssues = this.scanResults.securityIssues.length;
        const highRisk = this.scanResults.securityIssues.filter(i => i.risk === 'High').length;
        
        let score = 100;
        score -= (highRisk * 20);
        score -= ((totalIssues - highRisk) * 10);
        
        return Math.max(0, score);
    }

    formatBytes(bytes) {
        if (bytes === 0) return '0 Bytes';
        
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    async generateReport() {
        const report = {
            ...this.scanResults,
            generatedAt: new Date().toISOString(),
            scanDuration: Date.now() - this.scanResults.scanDate.getTime()
        };
        
        // Save detailed report
        fs.writeFileSync(
            `website-scan-report-${Date.now()}.json`,
            JSON.stringify(report, null, 2)
        );
        
        // Generate HTML report
        await this.generateHTMLReport(report);
    }

    async generateHTMLReport(report) {
        const htmlContent = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Website File Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; text-align: center; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 20px 0; }
        .stat-card { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .stat-number { font-size: 2em; font-weight: bold; color: #667eea; }
        .section { background: white; margin: 20px 0; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .error { color: #e74c3c; }
        .warning { color: #f39c12; }
        .success { color: #27ae60; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f8f9fa; }
        .progress-bar { width: 100%; height: 20px; background: #e9ecef; border-radius: 10px; overflow: hidden; }
        .progress-fill { height: 100%; background: linear-gradient(90deg, #667eea, #764ba2); }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Website File Scan Report</h1>
            <p>Generated on ${new Date().toLocaleString()}</p>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number">${report.totalFiles}</div>
                <div>Total Files</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">${this.formatBytes(report.totalSize)}</div>
                <div>Total Size</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">${report.directories.length}</div>
                <div>Directories</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">${report.insights.securityScore}%</div>
                <div>Security Score</div>
            </div>
        </div>

        <div class="section">
            <h3>📊 File Types Distribution</h3>
            <table>
                <tr><th>Type</th><th>Count</th><th>Size</th><th>Percentage</th></tr>
                ${Object.entries(report.fileTypes).map(([type, data]) => `
                    <tr>
                        <td>${type}</td>
                        <td>${data.count}</td>
                        <td>${this.formatBytes(data.size)}</td>
                        <td>${((data.count / report.totalFiles) * 100).toFixed(1)}%</td>
                    </tr>
                `).join('')}
            </table>
        </div>

        ${report.errors.length > 0 ? `
        <div class="section">
            <h3 class="error">❌ Errors Found (${report.errors.length})</h3>
            <table>
                <tr><th>Type</th><th>Path</th><th>Message</th></tr>
                ${report.errors.map(error => `
                    <tr>
                        <td>${error.type}</td>
                        <td>${error.path}</td>
                        <td>${error.message}</td>
                    </tr>
                `).join('')}
            </table>
        </div>
        ` : ''}

        ${report.securityIssues.length > 0 ? `
        <div class="section">
            <h3 class="warning">🔒 Security Issues (${report.securityIssues.length})</h3>
            <table>
                <tr><th>Type</th><th>Path</th><th>Risk</th><th>Description</th></tr>
                ${report.securityIssues.map(issue => `
                    <tr>
                        <td>${issue.type}</td>
                        <td>${issue.path}</td>
                        <td class="${issue.risk === 'High' ? 'error' : 'warning'}">${issue.risk}</td>
                        <td>${issue.description}</td>
                    </tr>
                `).join('')}
            </table>
        </div>
        ` : ''}

        ${report.duplicates.length > 0 ? `
        <div class="section">
            <h3 class="warning">🔄 Duplicate Files (${report.duplicates.length})</h3>
            <table>
                <tr><th>Original</th><th>Duplicate</th><th>Size</th></tr>
                ${report.duplicates.map(dup => `
                    <tr>
                        <td>${dup.original}</td>
                        <td>${dup.duplicate}</td>
                        <td>${dup.size}</td>
                    </tr>
                `).join('')}
            </table>
        </div>
        ` : ''}

        <div class="section">
            <h3>📁 Largest Directories</h3>
            <table>
                <tr><th>Path</th><th>Size</th><th>Files</th></tr>
                ${report.directories
                    .sort((a, b) => b.size - a.size)
                    .slice(0, 10)
                    .map(dir => `
                    <tr>
                        <td>${dir.path}</td>
                        <td>${this.formatBytes(dir.size)}</td>
                        <td>${dir.fileCount}</td>
                    </tr>
                `).join('')}
            </table>
        </div>

        ${report.largeFiles.length > 0 ? `
        <div class="section">
            <h3 class="warning">📦 Large Files (${report.largeFiles.length})</h3>
            <table>
                <tr><th>Path</th><th>Size</th><th>Type</th></tr>
                ${report.largeFiles.map(file => `
                    <tr>
                        <td>${file.path}</td>
                        <td>${file.size}</td>
                        <td>${file.type}</td>
                    </tr>
                `).join('')}
            </table>
        </div>
        ` : ''}

        <div class="section">
            <h3 class="success">✅ Scan Summary</h3>
            <p><strong>Most Common File Type:</strong> ${report.insights.mostCommonFileType.type} (${report.insights.mostCommonFileType.count} files)</p>
            <p><strong>Average File Size:</strong> ${this.formatBytes(report.insights.averageFileSize)}</p>
            <p><strong>Scan Duration:</strong> ${(report.scanDuration / 1000).toFixed(2)} seconds</p>
            <p><strong>Security Score:</strong> ${report.insights.securityScore}%</p>
        </div>
    </div>
</body>
</html>`;

        fs.writeFileSync(`website-scan-report-${Date.now()}.html`, htmlContent);
    }

    printScanSummary() {
        console.log('\n📊 WEBSITE FILE SCAN COMPLETE');
        console.log('=' * 60);
        console.log(`📁 Total Files Scanned: ${this.scanResults.totalFiles}`);
        console.log(`💾 Total Size: ${this.formatBytes(this.scanResults.totalSize)}`);
        console.log(`📂 Directories: ${this.scanResults.directories.length}`);
        console.log(`❌ Errors: ${this.scanResults.errors.length}`);
        console.log(`⚠️  Warnings: ${this.scanResults.warnings.length}`);
        console.log(`🔒 Security Issues: ${this.scanResults.securityIssues.length}`);
        console.log(`🔄 Duplicate Files: ${this.scanResults.duplicates.length}`);
        console.log(`🔐 Security Score: ${this.scanResults.insights.securityScore}%`);
        
        console.log('\n📋 File Types:');
        Object.entries(this.scanResults.fileTypes).forEach(([type, data]) => {
            console.log(`   ${type}: ${data.count} files (${this.formatBytes(data.size)})`);
        });
        
        console.log('\n✅ Scan reports generated:');
        console.log('   - JSON report saved');
        console.log('   - HTML report saved');
        console.log('=' * 60);
    }
}

// Export for use in other modules
module.exports = WebsiteFileScanner;

// Run scan if called directly
if (require.main === module) {
    const scanner = new WebsiteFileScanner();
    scanner.scanAllFiles();
}
