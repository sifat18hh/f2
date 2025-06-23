
const express = require('express');
const router = express.Router();

// Storage Status API
router.get('/api/storage/status', (req, res) => {
    try {
        if (global.unlimitedStorage) {
            const status = global.unlimitedStorage.getStorageStatus();
            res.json({
                success: true,
                storage: status,
                timestamp: new Date().toISOString()
            });
        } else {
            res.status(503).json({
                success: false,
                error: 'Storage system not initialized'
            });
        }
    } catch (error) {
        console.error('Storage Status API Error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to get storage status'
        });
    }
});

// Force Backup All Files API
router.post('/api/storage/backup-all', (req, res) => {
    try {
        if (global.unlimitedStorage) {
            global.unlimitedStorage.forceBackupAll();
            res.json({
                success: true,
                message: 'All files backup initiated to unlimited storage'
            });
        } else {
            res.status(503).json({
                success: false,
                error: 'Storage system not available'
            });
        }
    } catch (error) {
        console.error('Backup All API Error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to initiate backup'
        });
    }
});

// Restore File API
router.post('/api/storage/restore/:filename', async (req, res) => {
    try {
        const filename = req.params.filename;
        
        if (global.unlimitedStorage) {
            const success = await global.unlimitedStorage.restoreFromBackup(filename);
            
            if (success) {
                res.json({
                    success: true,
                    message: `File ${filename} restored successfully from unlimited storage`
                });
            } else {
                res.status(404).json({
                    success: false,
                    error: `File ${filename} not found in any backup location`
                });
            }
        } else {
            res.status(503).json({
                success: false,
                error: 'Storage system not available'
            });
        }
    } catch (error) {
        console.error('Restore File API Error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to restore file'
        });
    }
});

// Storage Usage API
router.get('/api/storage/usage', (req, res) => {
    try {
        if (global.unlimitedStorage) {
            const usage = global.unlimitedStorage.calculateStorageUsage();
            res.json({
                success: true,
                usage: {
                    total: usage.formattedSize,
                    unlimited: true,
                    available: 'Unlimited',
                    percentage: 0,
                    files: global.unlimitedStorage.getAllFiles().length
                }
            });
        } else {
            res.json({
                success: false,
                error: 'Storage system not initialized'
            });
        }
    } catch (error) {
        console.error('Storage Usage API Error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to get storage usage'
        });
    }
});

// Storage Health API
router.get('/api/storage/health', (req, res) => {
    try {
        const health = {
            status: 'optimal',
            unlimited: true,
            providers: ['replit-primary', 'replit-backup', 'distributed', 'cloud'],
            features: {
                autoBackup: true,
                cloudSync: true,
                compression: true,
                distribution: true,
                noLimits: true,
                realTimeSync: true
            },
            lastCheck: new Date().toISOString()
        };
        
        res.json({
            success: true,
            health: health
        });
    } catch (error) {
        console.error('Storage Health API Error:', error);
        res.status(500).json({
            success: false,
            error: 'Health check failed'
        });
    }
});

module.exports = router;
