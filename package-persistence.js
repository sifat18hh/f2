
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

class PackagePersistenceManager {
    constructor() {
        this.packageBackupDir = './package_backup';
        this.packageLockPath = './package-lock.json';
        this.nodeModulesPath = './node_modules';
        this.packageJsonPath = './package.json';
        
        // Ensure basic setup
        this.ensureDirectories();
        this.init();
    }

    ensureDirectories() {
        try {
            // Create backup directory if not exists
            if (!fs.existsSync(this.packageBackupDir)) {
                fs.mkdirSync(this.packageBackupDir, { recursive: true });
                console.log('📁 Created backup directory');
            }

            // Ensure package.json exists
            if (!fs.existsSync(this.packageJsonPath)) {
                const defaultPackageJson = {
                    "name": "tubeclone",
                    "version": "1.0.0",
                    "description": "TubeClone Video Platform",
                    "main": "index.js",
                    "scripts": {
                        "start": "node index.js",
                        "dev": "node index.js"
                    },
                    "dependencies": {
                        "express": "^4.18.2",
                        "multer": "^1.4.5-lts.1",
                        "express-session": "^1.17.3",
                        "bcrypt": "^5.1.0",
                        "express-rate-limit": "^6.7.0",
                        "compression": "^1.7.4"
                    },
                    "author": "TubeClone Team",
                    "license": "MIT"
                };
                fs.writeFileSync(this.packageJsonPath, JSON.stringify(defaultPackageJson, null, 2));
                console.log('📄 Created package.json');
            }
        } catch (error) {
            console.error('❌ Directory setup error:', error.message);
        }
    }

    init() {
        console.log('📦 Initializing Package Persistence System...');
        
        try {
            // Watch for package changes
            this.watchPackageChanges();
            
            // Restore packages if missing
            this.restorePackagesIfNeeded();
        } catch (error) {
            console.error('❌ Initialization error:', error.message);
        }
    }

    // Backup current packages
    backupPackages() {
        try {
            console.log('💾 Backing up packages...');
            
            // Backup package-lock.json if exists
            if (fs.existsSync(this.packageLockPath)) {
                const backupLockPath = path.join(this.packageBackupDir, 'package-lock.json');
                fs.copyFileSync(this.packageLockPath, backupLockPath);
                console.log('✅ Package-lock.json backed up');
            }

            // Create package info backup
            if (fs.existsSync(this.packageJsonPath)) {
                const packageInfo = this.getInstalledPackageInfo();
                const backupInfoPath = path.join(this.packageBackupDir, 'installed-packages.json');
                fs.writeFileSync(backupInfoPath, JSON.stringify(packageInfo, null, 2));
                console.log('✅ Package info backed up');
            }

            console.log('✅ Packages backed up successfully');
            return true;
        } catch (error) {
            console.error('❌ Backup failed:', error.message);
            return false;
        }
    }

    // Get installed package information
    getInstalledPackageInfo() {
        try {
            const packageData = fs.readFileSync(this.packageJsonPath, 'utf8');
            const packageJson = JSON.parse(packageData);
            
            return {
                dependencies: packageJson.dependencies || {},
                devDependencies: packageJson.devDependencies || {},
                timestamp: new Date().toISOString(),
                nodeVersion: process.version
            };
        } catch (error) {
            console.error('❌ Error reading package info:', error.message);
            return {
                dependencies: {},
                devDependencies: {},
                timestamp: new Date().toISOString(),
                nodeVersion: process.version,
                error: error.message
            };
        }
    }

    // Check if packages need restoration
    restorePackagesIfNeeded() {
        try {
            const needsRestore = !fs.existsSync(this.nodeModulesPath) || 
                               fs.readdirSync(this.nodeModulesPath).length === 0;
            
            if (needsRestore) {
                console.log('🔄 Node modules missing, checking for backup...');
                
                if (this.hasBackup()) {
                    console.log('📦 Backup found, restoring packages...');
                    this.restorePackages();
                } else {
                    console.log('📥 No backup found, installing fresh packages...');
                    this.installFresh();
                }
            } else {
                console.log('✅ Packages already installed');
            }
        } catch (error) {
            console.error('❌ Restore check failed:', error.message);
        }
    }

    // Check if backup exists
    hasBackup() {
        const backupLockPath = path.join(this.packageBackupDir, 'package-lock.json');
        const backupInfoPath = path.join(this.packageBackupDir, 'installed-packages.json');
        
        return fs.existsSync(backupLockPath) || fs.existsSync(backupInfoPath);
    }

    // Restore packages from backup
    restorePackages() {
        try {
            console.log('📦 Restoring packages from backup...');

            // Restore package-lock.json if exists
            const backupLockPath = path.join(this.packageBackupDir, 'package-lock.json');
            if (fs.existsSync(backupLockPath)) {
                fs.copyFileSync(backupLockPath, this.packageLockPath);
                console.log('✅ Package-lock.json restored');
            }

            // Install packages
            this.runNpmInstall();
            
            console.log('✅ Packages restored successfully');
            
            // Create fresh backup after successful restore
            setTimeout(() => {
                this.backupPackages();
            }, 2000);
            
        } catch (error) {
            console.error('❌ Package restoration failed:', error.message);
            console.log('🔄 Attempting fallback installation...');
            this.installFresh();
        }
    }

    // Install fresh packages
    installFresh() {
        try {
            console.log('📥 Installing fresh packages...');
            this.runNpmInstall();
            console.log('✅ Fresh installation completed');
            
            // Create backup after installation
            setTimeout(() => {
                this.backupPackages();
            }, 2000);
            
        } catch (error) {
            console.error('❌ Fresh installation failed:', error.message);
        }
    }

    // Run npm install with proper error handling
    runNpmInstall() {
        try {
            console.log('📥 Running npm install...');
            execSync('npm install', { 
                stdio: 'pipe',
                cwd: process.cwd(),
                timeout: 300000 // 5 minutes timeout
            });
            console.log('✅ npm install completed');
        } catch (error) {
            console.log('⚠️ Standard install failed, trying with --force...');
            try {
                execSync('npm install --force', { 
                    stdio: 'pipe',
                    cwd: process.cwd(),
                    timeout: 300000
                });
                console.log('✅ Force install completed');
            } catch (forceError) {
                console.error('❌ All install attempts failed:', forceError.message);
                throw forceError;
            }
        }
    }

    // Watch for package changes
    watchPackageChanges() {
        try {
            // Watch package.json changes
            if (fs.existsSync(this.packageJsonPath)) {
                fs.watchFile(this.packageJsonPath, (curr, prev) => {
                    console.log('📝 Package.json changed, creating backup in 3 seconds...');
                    setTimeout(() => {
                        this.backupPackages();
                    }, 3000);
                });
            }

            // Watch package-lock.json changes
            if (fs.existsSync(this.packageLockPath)) {
                fs.watchFile(this.packageLockPath, (curr, prev) => {
                    console.log('🔒 Package-lock.json changed, creating backup in 2 seconds...');
                    setTimeout(() => {
                        this.backupPackages();
                    }, 2000);
                });
            }
        } catch (error) {
            console.error('❌ File watch setup failed:', error.message);
        }
    }

    // Manual package installation with backup
    installPackage(packageName, isDev = false) {
        try {
            console.log(`📦 Installing ${packageName}...`);
            
            const flag = isDev ? '--save-dev' : '--save';
            const command = `npm install ${packageName} ${flag}`;
            
            execSync(command, { 
                stdio: 'inherit',
                cwd: process.cwd(),
                timeout: 180000 // 3 minutes timeout
            });
            
            console.log(`✅ ${packageName} installed successfully`);
            
            // Create backup after installation
            setTimeout(() => {
                this.backupPackages();
            }, 2000);
            
            return true;
        } catch (error) {
            console.error(`❌ Failed to install ${packageName}:`, error.message);
            return false;
        }
    }

    // Force restore from backup
    forceRestore() {
        try {
            console.log('💪 Force restoring packages...');
            
            // Remove existing node_modules
            if (fs.existsSync(this.nodeModulesPath)) {
                console.log('🗑️ Removing existing node_modules...');
                fs.rmSync(this.nodeModulesPath, { recursive: true, force: true });
            }
            
            // Remove package-lock.json
            if (fs.existsSync(this.packageLockPath)) {
                fs.unlinkSync(this.packageLockPath);
            }
            
            this.restorePackages();
            return true;
        } catch (error) {
            console.error('❌ Force restore failed:', error.message);
            return false;
        }
    }

    // Get detailed backup status
    getBackupStatus() {
        try {
            const backupLockPath = path.join(this.packageBackupDir, 'package-lock.json');
            const backupInfoPath = path.join(this.packageBackupDir, 'installed-packages.json');
            
            const status = {
                hasBackup: fs.existsSync(this.packageBackupDir),
                hasPackageLockBackup: fs.existsSync(backupLockPath),
                hasPackageInfo: fs.existsSync(backupInfoPath),
                nodeModulesExists: fs.existsSync(this.nodeModulesPath),
                packageJsonExists: fs.existsSync(this.packageJsonPath),
                backupDir: this.packageBackupDir,
                timestamp: new Date().toISOString()
            };

            // Get backup file sizes if they exist
            if (status.hasPackageLockBackup) {
                status.packageLockSize = fs.statSync(backupLockPath).size;
            }
            
            if (status.hasPackageInfo) {
                status.packageInfoSize = fs.statSync(backupInfoPath).size;
            }

            // Check node_modules size
            if (status.nodeModulesExists) {
                try {
                    const nodeModulesContents = fs.readdirSync(this.nodeModulesPath);
                    status.nodeModulesCount = nodeModulesContents.length;
                } catch (error) {
                    status.nodeModulesCount = 'Unable to read';
                }
            }
            
            return status;
        } catch (error) {
            console.error('Error getting backup status:', error.message);
            return {
                error: error.message,
                hasBackup: false,
                hasPackageLockBackup: false,
                hasPackageInfo: false,
                nodeModulesExists: false,
                packageJsonExists: false,
                backupDir: this.packageBackupDir,
                timestamp: new Date().toISOString()
            };
        }
    }
}

module.exports = PackagePersistenceManager;
