
const fs = require('fs');
const path = require('path');

class SecurityAudit {
    constructor() {
        this.securityIssues = [];
        this.recommendations = [];
    }

    async runAudit() {
        console.log('🔍 Running security audit...');
        
        this.checkSensitiveFiles();
        this.checkCodePatterns();
        this.checkFilePermissions();
        this.generateSecurityReport();
        
        console.log('✅ Security audit completed!');
    }

    checkSensitiveFiles() {
        const sensitivePatterns = [
            'password', 'secret', 'key', 'token', 'credential',
            'api_key', 'private_key', 'auth'
        ];
        
        const files = this.getAllFiles('.');
        
        files.forEach(file => {
            const filename = path.basename(file).toLowerCase();
            
            if (sensitivePatterns.some(pattern => filename.includes(pattern))) {
                this.securityIssues.push({
                    type: 'Sensitive File Exposure',
                    file: file,
                    severity: 'HIGH',
                    description: 'File may contain sensitive information'
                });
            }
        });
    }

    checkCodePatterns() {
        const dangerousPatterns = [
            /eval\s*\(/g,
            /exec\s*\(/g,
            /system\s*\(/g,
            /child_process\.exec/g
        ];
        
        const jsFiles = this.getAllFiles('.').filter(f => f.endsWith('.js'));
        
        jsFiles.forEach(file => {
            try {
                const content = fs.readFileSync(file, 'utf8');
                
                dangerousPatterns.forEach(pattern => {
                    if (pattern.test(content)) {
                        this.securityIssues.push({
                            type: 'Dangerous Code Pattern',
                            file: file,
                            severity: 'MEDIUM',
                            pattern: pattern.source,
                            description: 'Potentially dangerous code execution'
                        });
                    }
                });
            } catch (error) {
                // Skip binary files
            }
        });
    }

    checkFilePermissions() {
        const criticalFiles = ['index.js', 'package.json', 'admin.html'];
        
        criticalFiles.forEach(file => {
            if (fs.existsSync(file)) {
                try {
                    const stats = fs.statSync(file);
                    // Check if file is world-writable
                    if (stats.mode & parseInt('002', 8)) {
                        this.securityIssues.push({
                            type: 'File Permission Issue',
                            file: file,
                            severity: 'MEDIUM',
                            description: 'File is world-writable'
                        });
                    }
                } catch (error) {
                    console.error(`Error checking permissions for ${file}`);
                }
            }
        });
    }

    getAllFiles(dir, files = []) {
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
        
        return files;
    }

    generateSecurityReport() {
        const report = {
            timestamp: new Date().toISOString(),
            totalIssues: this.securityIssues.length,
            highSeverity: this.securityIssues.filter(i => i.severity === 'HIGH').length,
            mediumSeverity: this.securityIssues.filter(i => i.severity === 'MEDIUM').length,
            issues: this.securityIssues,
            recommendations: [
                'Move sensitive data to environment variables',
                'Remove or secure backup files with credentials',
                'Implement proper input validation',
                'Regular security audits',
                'Use HTTPS in production',
                'Implement rate limiting'
            ]
        };
        
        fs.writeFileSync('security-audit-report.json', JSON.stringify(report, null, 2));
        
        console.log('\n🔒 Security Audit Results:');
        console.log('================================');
        console.log(`Total Issues: ${report.totalIssues}`);
        console.log(`High Severity: ${report.highSeverity}`);
        console.log(`Medium Severity: ${report.mediumSeverity}`);
        console.log('================================');
        
        if (report.totalIssues > 0) {
            console.log('\n⚠️ Issues Found:');
            this.securityIssues.forEach((issue, index) => {
                console.log(`${index + 1}. [${issue.severity}] ${issue.type}`);
                console.log(`   File: ${issue.file}`);
                console.log(`   Description: ${issue.description}\n`);
            });
        }
    }
}

// Run security audit
if (require.main === module) {
    const audit = new SecurityAudit();
    audit.runAudit();
}

module.exports = SecurityAudit;
