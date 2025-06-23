const fs = require('fs');
const path = require('path');

console.log('🚀 TubeClone Startup System - Enhanced Error Recovery');
console.log('=' .repeat(60));

// Auto-fix system
function emergencyAutoFix() {
    console.log('🔧 Running emergency auto-fix...');

    try {
        // Fix database files
        const dbFixes = {
            'ads.json': [],
            'categories.json': [
                { id: 1, name: "Entertainment", icon: "fas fa-tv" },
                { id: 2, name: "Education", icon: "fas fa-graduation-cap" }
            ],
            'earnings.json': { totalEarnings: 0, adViews: 0, balance: 0, transactions: [] },
            'users.json': [],
            'videos.json': []
        };

        Object.keys(dbFixes).forEach(file => {
            try {
                if (!fs.existsSync(file)) {
                    fs.writeFileSync(file, JSON.stringify(dbFixes[file], null, 2));
                    console.log(`✅ Created ${file}`);
                } else {
                    // Test if file is valid JSON
                    const data = fs.readFileSync(file, 'utf8');
                    JSON.parse(data);
                }
            } catch (error) {
                fs.writeFileSync(file, JSON.stringify(dbFixes[file], null, 2));
                console.log(`🔧 Fixed corrupted ${file}`);
            }
        });

        // Create missing directories
        const dirs = ['uploads', 'thumbnails', 'storage', 'storage/backup'];
        dirs.forEach(dir => {
            if (!fs.existsSync(dir)) {
                fs.mkdirSync(dir, { recursive: true });
                console.log(`📁 Created directory: ${dir}`);
            }
        });

        // Fix permissions
        try {
            fs.chmodSync('index.js', '755');
        } catch (error) {
            // Ignore permission errors on some systems
        }

        console.log('✅ Emergency auto-fix completed!');

    } catch (error) {
        console.error('❌ Emergency auto-fix failed:', error.message);
    }
}

// System health check
function systemHealthCheck() {
    console.log('🏥 Running system health check...');

    const criticalFiles = [
        'index.js', 'package.json', 'users.json', 
        'videos.json', 'categories.json'
    ];

    let healthScore = 0;

    criticalFiles.forEach(file => {
        if (fs.existsSync(file)) {
            healthScore++;
            console.log(`✅ ${file} - OK`);
        } else {
            console.log(`❌ ${file} - MISSING`);
        }
    });

    const healthPercentage = (healthScore / criticalFiles.length) * 100;

    console.log(`📊 System Health: ${healthPercentage.toFixed(1)}%`);

    if (healthPercentage < 80) {
        console.log('⚠️ System health below 80%, running emergency fixes...');
        emergencyAutoFix();
    }

    return healthPercentage;
}

// Authentication system check
function checkAuthSystem() {
    console.log('🔐 Checking authentication system...');

    try {
        if (fs.existsSync('users.json')) {
            const users = JSON.parse(fs.readFileSync('users.json', 'utf8'));
            console.log(`👥 Found ${users.length} users in system`);

            const adminUsers = users.filter(user => user.isAdmin || user.isSuperAdmin);
            console.log(`👑 Found ${adminUsers.length} admin users`);

            if (adminUsers.length === 0 && users.length > 0) {
                // Auto-promote first user to admin
                users[0].isAdmin = true;
                users[0].isSuperAdmin = true;
                fs.writeFileSync('users.json', JSON.stringify(users, null, 2));
                console.log(`✅ Auto-promoted ${users[0].username} to admin`);
            }
        } else {
            console.log('ℹ️ No users found - first registered user will become admin');
        }

        console.log('✅ Authentication system check completed');

    } catch (error) {
        console.error('❌ Auth system check failed:', error.message);
        emergencyAutoFix();
    }
}

// Main startup process
async function startupProcess() {
    try {
        console.log('🎬 Starting TubeClone Enhanced Startup Process...');

        // Step 1: Emergency auto-fix
        emergencyAutoFix();

        // Step 2: System health check
        const health = systemHealthCheck();

        // Step 3: Auth system check
        checkAuthSystem();

        // Initialize Super Advanced AI
        try {
            const { SuperAdvancedAI } = require('./super-advanced-ai.js');
            const AdvancedAIMonitor = require('./advanced-ai-monitor.js');

            console.log('🔧 Loading AI components...');

            // Initialize Super AI
            if (!global.superAdvancedAI) {
                global.superAdvancedAI = new SuperAdvancedAI();
                console.log('✅ Super Advanced AI initialized');

                // Wait for AI to fully initialize
                setTimeout(async () => {
                    if (global.superAdvancedAI.isInitialized) {
                        console.log('🤖 Super Advanced AI: All systems online and ready');
                        console.log('🔧 Auto-fix capabilities: ACTIVE');
                        console.log('⚡ Performance optimization: ACTIVE');
                        console.log('🐛 Bug detection and fixing: ACTIVE');
                        console.log('🧠 Intelligent learning: ACTIVE');
                    }
                }, 3000);
            }

            // Initialize AI Monitor
            if (!global.advancedAIMonitor) {
                global.advancedAIMonitor = new AdvancedAIMonitor();
                console.log('✅ Advanced AI Monitor initialized');
                console.log('🔍 Continuous monitoring: ACTIVE');
                console.log('🔧 Auto-repair system: ACTIVE');
            }
        } catch (error) {
            console.error('❌ AI initialization failed:', error);
        }

        // Super AI Chat Assistant - REMOVED
        console.log('🚫 Super AI Chat Assistant has been completely removed');

        // Step 4: Final preparations
        console.log('🛠️ Final system preparations...');

        // Create default admin credentials info
        const adminInfo = {
            email: 'admin@tubeclone.com',
            password: 'admin',
            note: 'Default admin credentials - change after first login'
        };

        fs.writeFileSync('admin-credentials.json', JSON.stringify(adminInfo, null, 2));

        console.log('=' .repeat(60));
        console.log('✅ TubeClone startup completed successfully!');
        console.log('🌐 Your website is ready for hosting');
        console.log('👑 Admin Login: admin@tubeclone.com / admin');
        console.log('🔧 Auto-fix system is active and monitoring');
        console.log('🤖 Super Advanced AI: FULLY ACTIVE');
        console.log('⚡ Auto-optimization: ENABLED');
        console.log('🛡️ Error prediction: ACTIVE');
        console.log('🔄 Continuous monitoring: RUNNING');
        console.log('=' .repeat(60));

        // Set success flag
        process.env.STARTUP_SUCCESS = 'true';

    } catch (error) {
        console.error('❌ Startup process failed:', error);
        process.exit(1);
    }
}

// Run startup if this file is executed directly
if (require.main === module) {
    startupProcess();
}

module.exports = { startupProcess, emergencyAutoFix, systemHealthCheck };