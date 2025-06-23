
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

class PackageManagerCLI {
    constructor() {
        this.packageBackupDir = path.join(__dirname, 'package_backup');
        this.packageJsonPath = path.join(__dirname, 'package.json');
        this.nodeModulesPath = path.join(__dirname, 'node_modules');
        
        // Ensure backup directory exists
        if (!fs.existsSync(this.packageBackupDir)) {
            fs.mkdirSync(this.packageBackupDir, { recursive: true });
        }
    }

    backup() {
        try {
            console.log('📦 Starting package backup...');
            
            // Backup package.json
            if (fs.existsSync(this.packageJsonPath)) {
                const packageJson = JSON.parse(fs.readFileSync(this.packageJsonPath, 'utf8'));
                fs.writeFileSync(
                    path.join(this.packageBackupDir, 'package.json'),
                    JSON.stringify(packageJson, null, 2)
                );
                console.log('✅ package.json backed up');
            }

            // Backup package-lock.json
            const packageLockPath = path.join(__dirname, 'package-lock.json');
            if (fs.existsSync(packageLockPath)) {
                fs.copyFileSync(
                    packageLockPath,
                    path.join(this.packageBackupDir, 'package-lock.json')
                );
                console.log('✅ package-lock.json backed up');
            }

            // Create installed packages snapshot
            const installedPackages = this.getInstalledPackages();
            fs.writeFileSync(
                path.join(this.packageBackupDir, 'installed-packages.json'),
                JSON.stringify(installedPackages, null, 2)
            );
            console.log('✅ Installed packages list backed up');

            // Save deployment info
            const deploymentInfo = {
                nodeVersion: process.version,
                platform: process.platform,
                architecture: process.arch,
                timestamp: new Date().toISOString(),
                backupVersion: '1.0.0'
            };
            
            fs.writeFileSync(
                path.join(this.packageBackupDir, 'deployment-info.json'),
                JSON.stringify(deploymentInfo, null, 2)
            );
            console.log('✅ Deployment info saved');

            console.log('\n🎉 Package backup completed successfully!');
            console.log(`📁 Backup saved to: ${this.packageBackupDir}`);
            
        } catch (error) {
            console.error('❌ Backup failed:', error.message);
            process.exit(1);
        }
    }

    restore() {
        try {
            console.log('🔄 Starting package restoration...');

            // Check if backup exists
            if (!fs.existsSync(this.packageBackupDir)) {
                console.error('❌ No backup directory found');
                process.exit(1);
            }

            // Restore package.json
            const backupPackageJson = path.join(this.packageBackupDir, 'package.json');
            if (fs.existsSync(backupPackageJson)) {
                fs.copyFileSync(backupPackageJson, this.packageJsonPath);
                console.log('✅ package.json restored');
            }

            // Restore package-lock.json
            const backupPackageLock = path.join(this.packageBackupDir, 'package-lock.json');
            const targetPackageLock = path.join(__dirname, 'package-lock.json');
            if (fs.existsSync(backupPackageLock)) {
                fs.copyFileSync(backupPackageLock, targetPackageLock);
                console.log('✅ package-lock.json restored');
            }

            // Install packages
            console.log('📥 Installing packages...');
            execSync('npm install', { 
                stdio: 'inherit',
                cwd: __dirname
            });
            
            console.log('\n🎉 Package restoration completed successfully!');
            
        } catch (error) {
            console.error('❌ Restoration failed:', error.message);
            process.exit(1);
        }
    }

    status() {
        try {
            console.log('📊 Package Manager Status\n');
            console.log('='.repeat(40));

            // Check backup directory
            console.log(`Backup Directory: ${fs.existsSync(this.packageBackupDir) ? '✅ Exists' : '❌ Missing'}`);
            
            // Check package.json
            console.log(`Package.json: ${fs.existsSync(this.packageJsonPath) ? '✅ Exists' : '❌ Missing'}`);
            
            // Check node_modules
            console.log(`Node Modules: ${fs.existsSync(this.nodeModulesPath) ? '✅ Exists' : '❌ Missing'}`);
            
            // Check backup files
            const backupFiles = [
                'package.json',
                'package-lock.json', 
                'installed-packages.json',
                'deployment-info.json'
            ];
            
            console.log('\nBackup Files:');
            backupFiles.forEach(file => {
                const filePath = path.join(this.packageBackupDir, file);
                const exists = fs.existsSync(filePath);
                const size = exists ? this.getFileSize(filePath) : 'N/A';
                console.log(`  ${file}: ${exists ? '✅' : '❌'} ${size}`);
            });

            // Show installed packages count
            if (fs.existsSync(this.nodeModulesPath)) {
                const packageCount = this.getInstalledPackageCount();
                console.log(`\nInstalled Packages: ${packageCount}`);
            }

            // Show Node.js info
            console.log(`\nNode.js Version: ${process.version}`);
            console.log(`Platform: ${process.platform}`);
            console.log(`Architecture: ${process.arch}`);

            console.log('\n='.repeat(40));
            
        } catch (error) {
            console.error('❌ Status check failed:', error.message);
        }
    }

    check() {
        return this.status();
    }

    getInstalledPackages() {
        try {
            if (fs.existsSync(this.packageJsonPath)) {
                const packageJson = JSON.parse(fs.readFileSync(this.packageJsonPath, 'utf8'));
                return {
                    dependencies: packageJson.dependencies || {},
                    devDependencies: packageJson.devDependencies || {},
                    timestamp: new Date().toISOString(),
                    nodeVersion: process.version
                };
            }
        } catch (error) {
            console.warn('Warning: Could not read package.json');
        }
        return { dependencies: {}, devDependencies: {} };
    }

    getInstalledPackageCount() {
        try {
            const dirs = fs.readdirSync(this.nodeModulesPath, { withFileTypes: true });
            return dirs.filter(dirent => dirent.isDirectory()).length;
        } catch (error) {
            return 0;
        }
    }

    getFileSize(filePath) {
        try {
            const stats = fs.statSync(filePath);
            const bytes = stats.size;
            if (bytes < 1024) return bytes + ' B';
            if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
            return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
        } catch (error) {
            return 'Unknown';
        }
    }
}

// CLI Interface
function main() {
    const args = process.argv.slice(2);
    const command = args[0];
    
    if (!command) {
        console.log('📦 TubeClone Package Manager CLI');
        console.log('');
        console.log('Usage:');
        console.log('  node package-manager-cli.js <command>');
        console.log('');
        console.log('Commands:');
        console.log('  backup   - Create backup of packages');
        console.log('  restore  - Restore packages from backup');
        console.log('  status   - Show current status');
        console.log('  check    - Same as status');
        console.log('');
        console.log('Examples:');
        console.log('  node package-manager-cli.js backup');
        console.log('  node package-manager-cli.js status');
        process.exit(0);
    }

    const manager = new PackageManagerCLI();

    switch (command.toLowerCase()) {
        case 'backup':
            manager.backup();
            break;
        case 'restore':
            manager.restore();
            break;
        case 'status':
        case 'check':
            manager.status();
            break;
        default:
            console.error(`❌ Unknown command: ${command}`);
            console.log('💡 Available commands: backup, restore, status, check');
            process.exit(1);
    }
}

// Handle errors gracefully
process.on('uncaughtException', (error) => {
    console.error('❌ Uncaught Error:', error.message);
    console.log('💡 Try running: node package-manager-cli.js status');
    process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('❌ Unhandled Rejection:', reason);
    console.log('💡 Try running: node package-manager-cli.js status');
    process.exit(1);
});

// Run if called directly
if (require.main === module) {
    main();
}

module.exports = PackageManagerCLI;
