
const fs = require('fs');
const { execSync } = require('child_process');
const PackagePersistenceManager = require('./package-persistence');

class DeploymentSetup {
    constructor() {
        this.packageManager = new PackagePersistenceManager();
        this.setup();
    }

    setup() {
        console.log('🚀 Setting up for GitHub deployment...');
        
        try {
            // Ensure all packages are installed and backed up
            this.ensurePackages();
            
            // Create production-ready package backup
            this.createProductionBackup();
            
            // Update .gitignore to include necessary files
            this.updateGitignore();
            
            // Create deployment configuration
            this.createDeploymentConfig();
            
            console.log('✅ Deployment setup completed successfully!');
            console.log('📁 Your project is now ready for GitHub deployment');
            
        } catch (error) {
            console.error('❌ Deployment setup failed:', error.message);
        }
    }

    ensurePackages() {
        console.log('📦 Ensuring all packages are properly installed...');
        
        try {
            execSync('npm install', { stdio: 'inherit' });
            this.packageManager.backupPackages();
            console.log('✅ Packages installed and backed up');
        } catch (error) {
            console.error('❌ Package installation failed:', error.message);
            throw error;
        }
    }

    createProductionBackup() {
        console.log('💾 Creating production backup...');
        
        // Ensure backup directory exists
        if (!fs.existsSync('./package_backup')) {
            fs.mkdirSync('./package_backup', { recursive: true });
        }

        // Copy important files to backup
        const filesToBackup = [
            'package.json',
            'package-lock.json'
        ];

        filesToBackup.forEach(file => {
            if (fs.existsSync(file)) {
                fs.copyFileSync(file, `./package_backup/${file}`);
                console.log(`✅ Backed up ${file}`);
            }
        });

        // Create deployment info
        const deploymentInfo = {
            timestamp: new Date().toISOString(),
            nodeVersion: process.version,
            platform: process.platform,
            packageCount: Object.keys(require('./package.json').dependencies || {}).length,
            status: 'ready-for-deployment'
        };

        fs.writeFileSync('./package_backup/deployment-info.json', JSON.stringify(deploymentInfo, null, 2));
        console.log('✅ Production backup created');
    }

    updateGitignore() {
        console.log('📝 Updating .gitignore for deployment...');
        
        const gitignoreContent = fs.readFileSync('.gitignore', 'utf8');
        
        // Ensure package_backup is NOT ignored (we want it in GitHub)
        if (gitignoreContent.includes('package_backup/')) {
            const updatedContent = gitignoreContent.replace(/^package_backup\/.*$/gm, '');
            fs.writeFileSync('.gitignore', updatedContent);
        }

        // Add deployment-specific ignores
        const deploymentIgnores = `
# Keep package backup for deployment
!package_backup/
!package_backup/*.json
!package_backup/package-lock.json

# Deployment logs
deploy.log
`;

        fs.appendFileSync('.gitignore', deploymentIgnores);
        console.log('✅ .gitignore updated for deployment');
    }

    createDeploymentConfig() {
        console.log('⚙️ Creating deployment configuration...');
        
        const deployConfig = {
            name: "TubeClone",
            type: "node",
            version: "20",
            buildCommand: "npm install && npm run backup",
            startCommand: "npm start",
            port: 5000,
            environment: "production",
            healthCheck: "/",
            packageBackup: true,
            autoRestore: true,
            env: {
                NODE_ENV: "production",
                PORT: "5000"
            }
        };

        // Create Vercel configuration
        const vercelConfig = {
            "version": 2,
            "builds": [
                {
                    "src": "index.js",
                    "use": "@vercel/node"
                }
            ],
            "routes": [
                {
                    "src": "/(.*)",
                    "dest": "/index.js"
                }
            ]
        };

        // Create Render configuration
        const renderConfig = {
            "services": [
                {
                    "type": "web",
                    "name": "tubeclone",
                    "env": "node",
                    "plan": "free",
                    "buildCommand": "npm install",
                    "startCommand": "npm start",
                    "healthCheckPath": "/",
                    "envVars": [
                        {
                            "key": "NODE_ENV",
                            "value": "production"
                        },
                        {
                            "key": "PORT",
                            "generateValue": true
                        }
                    ]
                }
            ]
        };

        fs.writeFileSync('./deploy.config.json', JSON.stringify(deployConfig, null, 2));
        fs.writeFileSync('./vercel.json', JSON.stringify(vercelConfig, null, 2));
        fs.writeFileSync('./render.yaml', JSON.stringify(renderConfig, null, 2));
        
        console.log('✅ Deployment configuration created for multiple platforms');
    }
}

// Run if called directly
if (require.main === module) {
    new DeploymentSetup();
}

module.exports = DeploymentSetup;
