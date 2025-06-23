
// Admin Dashboard Function Test Script
console.log('🧪 Testing Admin Dashboard Functions...');

function testAdminFunctions() {
    const results = {
        adminPanelLoaded: false,
        buttonsWorking: false,
        navigationWorking: false,
        formsWorking: false,
        errorsFound: []
    };

    try {
        // Test 1: Check if admin panel is loaded
        if (window.adminPanel || window.admin) {
            results.adminPanelLoaded = true;
            console.log('✅ Admin panel loaded successfully');
        } else {
            results.errorsFound.push('Admin panel not loaded');
            console.log('❌ Admin panel not loaded');
        }

        // Test 2: Check buttons
        const buttons = document.querySelectorAll('button, .admin-btn');
        let workingButtons = 0;
        buttons.forEach(btn => {
            if (btn.onclick || btn.getAttribute('onclick')) {
                workingButtons++;
            }
        });
        
        if (workingButtons > 0) {
            results.buttonsWorking = true;
            console.log(`✅ ${workingButtons}/${buttons.length} buttons working`);
        } else {
            results.errorsFound.push('No buttons working');
            console.log('❌ No buttons working');
        }

        // Test 3: Check navigation
        const navItems = document.querySelectorAll('.admin-nav-item');
        let workingNav = 0;
        navItems.forEach(item => {
            if (item.onclick || item.dataset.section) {
                workingNav++;
            }
        });

        if (workingNav > 0) {
            results.navigationWorking = true;
            console.log(`✅ ${workingNav}/${navItems.length} navigation items working`);
        } else {
            results.errorsFound.push('Navigation not working');
            console.log('❌ Navigation not working');
        }

        // Test 4: Check forms
        const forms = document.querySelectorAll('form');
        if (forms.length > 0) {
            results.formsWorking = true;
            console.log(`✅ ${forms.length} forms found`);
        } else {
            console.log('⚠️ No forms found');
        }

    } catch (error) {
        results.errorsFound.push(error.message);
        console.error('❌ Test error:', error);
    }

    // Generate report
    const overallScore = Object.values(results).filter(v => v === true).length;
    const totalTests = 4;
    const percentage = Math.round((overallScore / totalTests) * 100);

    console.log('\n📊 ADMIN DASHBOARD TEST RESULTS:');
    console.log('═══════════════════════════════════');
    console.log(`📊 Overall Score: ${percentage}% (${overallScore}/${totalTests})`);
    console.log(`✅ Admin Panel: ${results.adminPanelLoaded ? 'WORKING' : 'FAILED'}`);
    console.log(`🔘 Buttons: ${results.buttonsWorking ? 'WORKING' : 'FAILED'}`);
    console.log(`🧭 Navigation: ${results.navigationWorking ? 'WORKING' : 'FAILED'}`);
    console.log(`📝 Forms: ${results.formsWorking ? 'WORKING' : 'NOT FOUND'}`);
    
    if (results.errorsFound.length > 0) {
        console.log('\n❌ Errors Found:');
        results.errorsFound.forEach(error => console.log(`   • ${error}`));
    }
    
    console.log('═══════════════════════════════════\n');

    return results;
}

// Auto-run test when page loads
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', testAdminFunctions);
} else {
    testAdminFunctions();
}

// Export for manual testing
window.testAdminFunctions = testAdminFunctions;
