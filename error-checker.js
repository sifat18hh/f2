
const fs = require('fs');
const path = require('path');

class ErrorChecker {
    constructor() {
        this.errors = [];
        this.warnings = [];
        this.fixes = [];
    }

    async checkAllFiles() {
        console.log('🔍 Starting comprehensive error check...');
        
        // Check database files
        this.checkDatabaseFiles();
        
        // Check server files
        this.checkServerFiles();
        
        // Check configuration files
        this.checkConfigFiles();
        
        // Check directories
        this.checkDirectories();
        
        // Auto-fix issues
        await this.autoFixIssues();
        
        this.printReport();
    }

    checkDatabaseFiles() {
        const dbFiles = [
            'videos.json', 'users.json', 'ads.json', 
            'categories.json', 'earnings.json'
        ];
        
        dbFiles.forEach(file => {
            try {
                if (fs.existsSync(file)) {
                    const data = JSON.parse(fs.readFileSync(file, 'utf8'));
                    console.log(`✅ ${file}: Valid`);
                } else {
                    this.errors.push(`Missing database file: ${file}`);
                    this.fixes.push(() => this.createDefaultDatabase(file));
                }
            } catch (error) {
                this.errors.push(`Corrupted database file: ${file} - ${error.message}`);
                this.fixes.push(() => this.repairDatabase(file));
            }
        });
    }

    checkServerFiles() {
        const serverFiles = ['index.js', 'package.json'];
        
        serverFiles.forEach(file => {
            if (!fs.existsSync(file)) {
                this.errors.push(`Missing critical file: ${file}`);
            } else {
                console.log(`✅ ${file}: Found`);
            }
        });
    }

    checkConfigFiles() {
        const configFiles = [
            'site-settings.json', 
            'seo-optimized-meta.json'
        ];
        
        configFiles.forEach(file => {
            try {
                if (fs.existsSync(file)) {
                    JSON.parse(fs.readFileSync(file, 'utf8'));
                    console.log(`✅ ${file}: Valid`);
                } else {
                    this.warnings.push(`Missing config file: ${file}`);
                }
            } catch (error) {
                this.errors.push(`Invalid config file: ${file}`);
            }
        });
    }

    checkDirectories() {
        const dirs = ['uploads', 'thumbnails', 'storage'];
        
        dirs.forEach(dir => {
            if (!fs.existsSync(dir)) {
                this.warnings.push(`Missing directory: ${dir}`);
                this.fixes.push(() => {
                    fs.mkdirSync(dir, { recursive: true });
                    console.log(`📁 Created directory: ${dir}`);
                });
            } else {
                console.log(`✅ Directory ${dir}: Found`);
            }
        });
    }

    createDefaultDatabase(filename) {
        let defaultData;
        
        switch (filename) {
            case 'videos.json':
                defaultData = [];
                break;
            case 'users.json':
                defaultData = [];
                break;
            case 'ads.json':
                defaultData = [];
                break;
            case 'categories.json':
                defaultData = [
                    { id: 1, name: "Entertainment", icon: "fas fa-tv" },
                    { id: 2, name: "Education", icon: "fas fa-graduation-cap" }
                ];
                break;
            case 'earnings.json':
                defaultData = { totalEarnings: 0, adViews: 0, balance: 0, transactions: [] };
                break;
            default:
                defaultData = {};
        }
        
        fs.writeFileSync(filename, JSON.stringify(defaultData, null, 2));
        console.log(`✅ Created default ${filename}`);
    }

    repairDatabase(filename) {
        // Backup corrupted file
        if (fs.existsSync(filename)) {
            fs.copyFileSync(filename, `${filename}.corrupted.backup`);
        }
        
        // Create new default file
        this.createDefaultDatabase(filename);
        console.log(`🔧 Repaired corrupted ${filename}`);
    }

    async autoFixIssues() {
        console.log('🔧 Auto-fixing detected issues...');
        
        for (const fix of this.fixes) {
            try {
                await fix();
            } catch (error) {
                console.error('❌ Auto-fix failed:', error.message);
            }
        }
    }

    printReport() {
        console.log('\n📊 Error Check Report:');
        console.log('='.repeat(40));
        
        if (this.errors.length === 0 && this.warnings.length === 0) {
            console.log('✅ No errors or warnings found!');
        } else {
            if (this.errors.length > 0) {
                console.log(`❌ Errors found: ${this.errors.length}`);
                this.errors.forEach(error => console.log(`   - ${error}`));
            }
            
            if (this.warnings.length > 0) {
                console.log(`⚠️ Warnings: ${this.warnings.length}`);
                this.warnings.forEach(warning => console.log(`   - ${warning}`));
            }
        }
        
        console.log(`🔧 Auto-fixes applied: ${this.fixes.length}`);
        console.log('='.repeat(40));
    }
}

// Run the error checker
const checker = new ErrorChecker();
checker.checkAllFiles();

module.exports = ErrorChecker;
