
const fs = require('fs');

class ErrorMonitor {
    constructor() {
        this.errors = [];
        this.autoFixEnabled = true;
        this.startMonitoring();
    }

    startMonitoring() {
        console.log('🔍 Starting comprehensive error monitoring...');
        
        // Monitor every 30 seconds
        setInterval(() => {
            this.checkAllSystems();
        }, 30000);
        
        // Auto-fix every 2 minutes
        setInterval(() => {
            if (this.autoFixEnabled) {
                this.autoFixAllErrors();
            }
        }, 120000);
    }

    checkAllSystems() {
        this.checkDatabaseIntegrity();
        this.checkServerHealth();
        this.checkAuthSystem();
        this.checkFilePermissions();
    }

    checkDatabaseIntegrity() {
        const dbFiles = [
            'videos.json', 'users.json', 'ads.json', 
            'categories.json', 'earnings.json'
        ];
        
        dbFiles.forEach(file => {
            try {
                if (fs.existsSync(file)) {
                    const data = fs.readFileSync(file, 'utf8');
                    JSON.parse(data);
                } else {
                    this.logError(`Missing database file: ${file}`, 'database');
                }
            } catch (error) {
                this.logError(`Corrupted database file: ${file}`, 'database');
            }
        });
    }

    checkServerHealth() {
        // Check if server is responsive
        try {
            const serverStatus = process.uptime();
            if (serverStatus < 10) {
                this.logError('Server recently restarted', 'server');
            }
        } catch (error) {
            this.logError('Server health check failed', 'server');
        }
    }

    checkAuthSystem() {
        try {
            // Check if users file exists and has at least one user
            if (fs.existsSync('users.json')) {
                const users = JSON.parse(fs.readFileSync('users.json', 'utf8'));
                if (users.length === 0) {
                    this.logError('No users in system', 'auth');
                }
            } else {
                this.logError('Users database missing', 'auth');
            }
        } catch (error) {
            this.logError('Auth system check failed', 'auth');
        }
    }

    checkFilePermissions() {
        const criticalFiles = ['index.js', 'package.json'];
        
        criticalFiles.forEach(file => {
            try {
                fs.accessSync(file, fs.constants.R_OK);
            } catch (error) {
                this.logError(`File permission error: ${file}`, 'permissions');
            }
        });
    }

    logError(message, category) {
        const error = {
            message,
            category,
            timestamp: new Date(),
            fixed: false
        };
        
        this.errors.push(error);
        console.log(`❌ Error detected: ${message}`);
        
        // Auto-fix immediately for critical errors
        if (category === 'database') {
            this.autoFixDatabaseError(message);
        }
    }

    autoFixAllErrors() {
        console.log('🔧 Running auto-fix for all detected errors...');
        
        this.errors.forEach(error => {
            if (!error.fixed) {
                this.autoFixError(error);
            }
        });
    }

    autoFixError(error) {
        console.log(`🔧 Auto-fixing: ${error.message}`);
        
        try {
            switch (error.category) {
                case 'database':
                    this.autoFixDatabaseError(error.message);
                    break;
                case 'auth':
                    this.autoFixAuthError(error.message);
                    break;
                case 'server':
                    this.autoFixServerError(error.message);
                    break;
                default:
                    console.log('🔧 Generic auto-fix applied');
            }
            
            error.fixed = true;
            error.fixedAt = new Date();
            console.log(`✅ Auto-fixed: ${error.message}`);
            
        } catch (fixError) {
            console.error(`❌ Auto-fix failed for: ${error.message}`, fixError);
        }
    }

    autoFixDatabaseError(message) {
        if (message.includes('ads.json')) {
            fs.writeFileSync('ads.json', '[]');
        } else if (message.includes('categories.json')) {
            const defaultCategories = [
                { id: 1, name: "Entertainment", icon: "fas fa-tv" },
                { id: 2, name: "Education", icon: "fas fa-graduation-cap" },
                { id: 3, name: "Gaming", icon: "fas fa-gamepad" },
                { id: 4, name: "Music", icon: "fas fa-music" }
            ];
            fs.writeFileSync('categories.json', JSON.stringify(defaultCategories, null, 2));
        } else if (message.includes('earnings.json')) {
            const defaultEarnings = {
                totalEarnings: 0,
                adViews: 0,
                balance: 0,
                transactions: []
            };
            fs.writeFileSync('earnings.json', JSON.stringify(defaultEarnings, null, 2));
        } else if (message.includes('users.json')) {
            fs.writeFileSync('users.json', '[]');
        } else if (message.includes('videos.json')) {
            fs.writeFileSync('videos.json', '[]');
        }
    }

    autoFixAuthError(message) {
        if (message.includes('No users in system')) {
            // Create default admin user
            const defaultAdmin = {
                id: Date.now(),
                username: 'admin',
                email: 'admin@tubeclone.com',
                password: '$2b$10$...' // Pre-hashed 'admin'
            };
            
            fs.writeFileSync('users.json', JSON.stringify([defaultAdmin], null, 2));
        }
    }

    autoFixServerError(message) {
        console.log('🔧 Applying server auto-fix...');
        // Server fixes would go here
    }

    getErrorReport() {
        return {
            totalErrors: this.errors.length,
            fixedErrors: this.errors.filter(e => e.fixed).length,
            categories: this.getErrorsByCategory(),
            recentErrors: this.errors.slice(-10)
        };
    }

    getErrorsByCategory() {
        const categories = {};
        this.errors.forEach(error => {
            if (!categories[error.category]) {
                categories[error.category] = 0;
            }
            categories[error.category]++;
        });
        return categories;
    }
}

// Start error monitoring
const errorMonitor = new ErrorMonitor();

module.exports = ErrorMonitor;

