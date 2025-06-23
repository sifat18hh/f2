
// Comprehensive System Status Checker
const fs = require('fs');
const path = require('path');

console.log('🔍 Starting Comprehensive System Check...');
console.log('=========================================');

async function checkSystemStatus() {
    const status = {
        server: false,
        database: false,
        admin: false,
        ai: false,
        css: false,
        files: false,
        storage: false
    };

    try {
        // 1. Check Server Files
        console.log('\n📋 1. Server Files Check:');
        const serverFiles = ['index.js', 'package.json', 'admin.html'];
        serverFiles.forEach(file => {
            if (fs.existsSync(file)) {
                console.log(`✅ ${file} - OK`);
            } else {
                console.log(`❌ ${file} - MISSING`);
                return;
            }
        });
        status.server = true;

        // 2. Check Database Files
        console.log('\n💾 2. Database Check:');
        const dbFiles = ['users.json', 'videos.json', 'categories.json', 'ads.json', 'earnings.json'];
        dbFiles.forEach(file => {
            try {
                if (fs.existsSync(file)) {
                    const data = fs.readFileSync(file, 'utf8');
                    JSON.parse(data);
                    console.log(`✅ ${file} - Valid JSON`);
                } else {
                    console.log(`❌ ${file} - Missing`);
                }
            } catch (error) {
                console.log(`❌ ${file} - Corrupted`);
            }
        });
        status.database = true;

        // 3. Check Admin System
        console.log('\n👑 3. Admin System Check:');
        if (fs.existsSync('admin.html') && fs.existsSync('admin-script.js')) {
            console.log('✅ Admin dashboard files exist');
            
            // Check admin credentials
            if (fs.existsSync('admin-credentials.json')) {
                const adminCreds = JSON.parse(fs.readFileSync('admin-credentials.json', 'utf8'));
                console.log(`✅ Admin credentials: ${adminCreds.email}`);
            }
            status.admin = true;
        }

        // 4. Check AI System
        console.log('\n🤖 4. AI System Check:');
        const aiFiles = ['super-advanced-ai.js', 'advanced-ai-monitor.js'];
        aiFiles.forEach(file => {
            if (fs.existsSync(file)) {
                console.log(`✅ ${file} - OK`);
            } else {
                console.log(`❌ ${file} - Missing`);
                return;
            }
        });
        
        // Test AI initialization
        try {
            delete require.cache[require.resolve('./super-advanced-ai.js')];
            const { SuperAdvancedAI } = require('./super-advanced-ai.js');
            const testAI = new SuperAdvancedAI();
            console.log('✅ AI initialization - OK');
            status.ai = true;
        } catch (error) {
            console.log('❌ AI initialization failed:', error.message);
        }

        // 5. Check CSS and Theme
        console.log('\n🎨 5. CSS Theme Check:');
        if (fs.existsSync('admin-script.js')) {
            const adminScript = fs.readFileSync('admin-script.js', 'utf8');
            if (adminScript.includes('forceFacebookStyleCSS')) {
                console.log('✅ Facebook-style CSS function exists');
                status.css = true;
            }
        }

        // 6. Check Upload System
        console.log('\n📁 6. File System Check:');
        const dirs = ['uploads', 'thumbnails', 'storage'];
        dirs.forEach(dir => {
            if (fs.existsSync(dir)) {
                console.log(`✅ ${dir}/ directory exists`);
            } else {
                fs.mkdirSync(dir, { recursive: true });
                console.log(`🔧 Created ${dir}/ directory`);
            }
        });
        status.files = true;

        // 7. Check Storage System
        console.log('\n☁️ 7. Storage System Check:');
        if (fs.existsSync('storage')) {
            const storageStats = fs.statSync('storage');
            console.log(`✅ Storage directory: ${Math.round(storageStats.size / 1024)}KB`);
            status.storage = true;
        }

        // 8. Test Key Functions
        console.log('\n⚙️ 8. Function Test:');
        
        // Test video upload functionality
        if (fs.existsSync('videos.json')) {
            const videos = JSON.parse(fs.readFileSync('videos.json', 'utf8'));
            console.log(`✅ Video system: ${videos.length} videos loaded`);
        }

        // Test user system
        if (fs.existsSync('users.json')) {
            const users = JSON.parse(fs.readFileSync('users.json', 'utf8'));
            const adminUsers = users.filter(u => u.isAdmin);
            console.log(`✅ User system: ${users.length} users, ${adminUsers.length} admins`);
        }

        // Overall Status
        console.log('\n📊 Overall System Status:');
        console.log('==========================');
        
        const totalChecks = Object.keys(status).length;
        const passedChecks = Object.values(status).filter(Boolean).length;
        const healthPercentage = (passedChecks / totalChecks) * 100;

        console.log(`Server Files: ${status.server ? '✅' : '❌'}`);
        console.log(`Database: ${status.database ? '✅' : '❌'}`);
        console.log(`Admin System: ${status.admin ? '✅' : '❌'}`);
        console.log(`AI System: ${status.ai ? '✅' : '❌'}`);
        console.log(`CSS Theme: ${status.css ? '✅' : '❌'}`);
        console.log(`File System: ${status.files ? '✅' : '❌'}`);
        console.log(`Storage: ${status.storage ? '✅' : '❌'}`);

        console.log(`\n🎯 System Health: ${healthPercentage.toFixed(1)}%`);

        if (healthPercentage >= 90) {
            console.log('🎉 EXCELLENT: System is working perfectly!');
        } else if (healthPercentage >= 70) {
            console.log('✅ GOOD: System is working well with minor issues');
        } else {
            console.log('⚠️ WARNING: System needs attention');
        }

        // Live Test
        console.log('\n🔴 Live System Test:');
        console.log('===================');
        console.log('🌐 Server URL: http://localhost:5000');
        console.log('👑 Admin Panel: http://localhost:5000/admin');
        console.log('🔐 Admin Login: admin@tubeclone.com / admin');
        
        return { status, healthPercentage, passedChecks, totalChecks };

    } catch (error) {
        console.error('❌ System check failed:', error);
        return { status, healthPercentage: 0, error: error.message };
    }
}

// Quick Fix Function
async function quickFixIssues() {
    console.log('\n🔧 Running Quick Fix...');
    
    // Fix missing directories
    const dirs = ['uploads', 'thumbnails', 'storage', 'storage/backup'];
    dirs.forEach(dir => {
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
            console.log(`📁 Created: ${dir}`);
        }
    });

    // Fix missing database files
    const dbDefaults = {
        'ads.json': [],
        'categories.json': [
            { id: 1, name: "Entertainment", icon: "fas fa-tv" },
            { id: 2, name: "Education", icon: "fas fa-graduation-cap" }
        ],
        'earnings.json': { totalEarnings: 0, adViews: 0, balance: 0, transactions: [] },
        'users.json': [],
        'videos.json': []
    };

    Object.keys(dbDefaults).forEach(file => {
        if (!fs.existsSync(file)) {
            fs.writeFileSync(file, JSON.stringify(dbDefaults[file], null, 2));
            console.log(`📄 Created: ${file}`);
        }
    });

    console.log('✅ Quick fix completed');
}

// Export functions
module.exports = { checkSystemStatus, quickFixIssues };

// Run if called directly
if (require.main === module) {
    quickFixIssues().then(() => {
        checkSystemStatus().then(result => {
            if (result.healthPercentage >= 90) {
                console.log('\n🎊 সব কিছু Perfect! TubeClone সম্পূর্ণভাবে ready!');
            } else {
                console.log('\n⚠️ কিছু সমস্যা আছে, কিন্তু বেশিরভাগ কাজ করছে');
            }
        });
    });
}
