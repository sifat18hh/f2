
#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

console.log('🤖 Super Advanced AI System Check');
console.log('==================================\n');

// Check file existence and sizes
function checkFiles() {
    console.log('📁 File Check:');
    
    const requiredFiles = [
        'super-advanced-ai.js',
        'advanced-ai-monitor.js',
        'init-super-ai.js',
        'index.js',
        'package.json'
    ];
    
    let allFilesExist = true;
    
    requiredFiles.forEach(file => {
        if (fs.existsSync(file)) {
            const stats = fs.statSync(file);
            const sizeKB = Math.round(stats.size / 1024);
            console.log(`✅ ${file} - ${sizeKB}KB`);
        } else {
            console.log(`❌ ${file} - Missing`);
            allFilesExist = false;
        }
    });
    
    return allFilesExist;
}

// Test AI initialization
async function testAIInitialization() {
    console.log('\n🧠 AI Initialization Check:');
    
    try {
        // Load the Super AI module
        delete require.cache[require.resolve('./super-advanced-ai.js')];
        const aiModule = require('./super-advanced-ai.js');
        
        if (typeof aiModule.SuperAdvancedAI !== 'undefined') {
            console.log('✅ SuperAdvancedAI is properly defined');
            
            // Test creating instances
            const testAI = new aiModule.SuperAdvancedAI();
            console.log('✅ AI instance created successfully');
            
            // Test basic functionality
            const status = testAI.getStatus();
            console.log('✅ AI status check working');
            
            return true;
        } else {
            console.log('❌ SuperAdvancedAI is not defined');
            return false;
        }
        
    } catch (error) {
        console.log(`❌ Error loading Super Advanced AI: ${error.message}`);
        return false;
    }
}

// Test AI Monitor
async function testAIMonitor() {
    console.log('\n🔍 AI Monitor Check:');
    
    try {
        delete require.cache[require.resolve('./advanced-ai-monitor.js')];
        const monitorModule = require('./advanced-ai-monitor.js');
        
        console.log('✅ Advanced AI Monitor loaded');
        return true;
    } catch (error) {
        console.log(`❌ Advanced AI Monitor error: ${error.message}`);
        return false;
    }
}

// Test server integration
function testServerIntegration() {
    console.log('\n🌐 Server Integration Check:');
    
    const indexPath = './index.js';
    
    if (!fs.existsSync(indexPath)) {
        console.log('❌ index.js not found');
        return false;
    }
    
    const indexContent = fs.readFileSync(indexPath, 'utf8');
    
    const checks = [
        { name: 'Super AI integration', pattern: /super-advanced-ai/ },
        { name: 'Express server setup', pattern: /express/ },
        { name: 'Port configuration', pattern: /listen/ }
    ];
    
    let allIntegrated = true;
    
    checks.forEach(check => {
        if (check.pattern.test(indexContent)) {
            console.log(`✅ ${check.name} found`);
        } else {
            console.log(`❌ ${check.name} not found`);
            allIntegrated = false;
        }
    });
    
    return allIntegrated;
}

// Run all checks
async function runSystemCheck() {
    try {
        const filesOK = checkFiles();
        const aiOK = await testAIInitialization();
        const monitorOK = await testAIMonitor();
        const serverOK = testServerIntegration();
        
        console.log('\n🏁 System Check Complete');
        console.log('========================');
        
        if (filesOK && aiOK && monitorOK && serverOK) {
            console.log('✅ All systems operational!');
            console.log('🚀 Super Advanced AI is ready to use');
            return true;
        } else {
            console.log('⚠️ Some issues detected');
            console.log('📝 Check the logs above for details');
            return false;
        }
    } catch (error) {
        console.error('❌ System check failed:', error.message);
        return false;
    }
}

// Export for module use
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { runSystemCheck };
}

// Run the check if called directly
if (require.main === module) {
    runSystemCheck().then(success => {
        process.exit(success ? 0 : 1);
    });
}
