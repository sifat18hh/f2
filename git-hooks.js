
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

class GitPackageHooks {
    constructor() {
        this.hooksDir = './.git/hooks';
        this.setupHooks();
    }

    setupHooks() {
        if (!fs.existsSync('./.git')) {
            console.log('📋 Git repository not initialized. Initializing...');
            try {
                execSync('git init', { stdio: 'inherit' });
            } catch (error) {
                console.error('❌ Failed to initialize git:', error.message);
                return;
            }
        }

        if (!fs.existsSync(this.hooksDir)) {
            fs.mkdirSync(this.hooksDir, { recursive: true });
        }

        this.createPreCommitHook();
        this.createPostCheckoutHook();
        this.createPostMergeHook();
    }

    createPreCommitHook() {
        const preCommitPath = path.join(this.hooksDir, 'pre-commit');
        const preCommitScript = `#!/bin/sh
# TubeClone Package Persistence - Pre Commit Hook

echo "📦 Backing up packages before commit..."
node -e "
try {
    const PackageManager = require('./package-persistence');
    const pm = new PackageManager();
    pm.backupPackages();
    console.log('✅ Package backup completed');
} catch (error) {
    console.error('❌ Package backup failed:', error.message);
}
"

# Add package backup to git
git add package_backup/ 2>/dev/null || true

echo "✅ Pre-commit package backup completed"
`;

        fs.writeFileSync(preCommitPath, preCommitScript);
        try {
            fs.chmodSync(preCommitPath, '755');
        } catch (error) {
            console.log('⚠️ Could not set executable permission for pre-commit hook');
        }
    }

    createPostCheckoutHook() {
        const postCheckoutPath = path.join(this.hooksDir, 'post-checkout');
        const postCheckoutScript = `#!/bin/sh
# TubeClone Package Persistence - Post Checkout Hook

echo "🔄 Checking packages after checkout..."
node -e "
try {
    const PackageManager = require('./package-persistence');
    const pm = new PackageManager();
    pm.restorePackagesIfNeeded();
    console.log('✅ Package check completed');
} catch (error) {
    console.error('❌ Package check failed:', error.message);
}
"
`;

        fs.writeFileSync(postCheckoutPath, postCheckoutScript);
        try {
            fs.chmodSync(postCheckoutPath, '755');
        } catch (error) {
            console.log('⚠️ Could not set executable permission for post-checkout hook');
        }
    }

    createPostMergeHook() {
        const postMergePath = path.join(this.hooksDir, 'post-merge');
        const postMergeScript = `#!/bin/sh
# TubeClone Package Persistence - Post Merge Hook

echo "🔄 Restoring packages after merge..."
node -e "
try {
    const PackageManager = require('./package-persistence');
    const pm = new PackageManager();
    pm.restorePackagesIfNeeded();
    console.log('✅ Package restoration completed');
} catch (error) {
    console.error('❌ Package restoration failed:', error.message);
}
"
`;

        fs.writeFileSync(postMergePath, postMergeScript);
        try {
            fs.chmodSync(postMergePath, '755');
        } catch (error) {
            console.log('⚠️ Could not set executable permission for post-merge hook');
        }
    }
}

module.exports = GitPackageHooks;
