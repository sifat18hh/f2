
const express = require('express');
const router = express.Router();

// Auto System Status API
router.get('/api/auto-system/status', (req, res) => {
    try {
        if (global.autoSystemManager) {
            const status = global.autoSystemManager.getSystemStatus();
            res.json({
                success: true,
                status: status,
                timestamp: new Date().toISOString()
            });
        } else {
            res.status(503).json({
                success: false,
                error: 'Auto System Manager not initialized'
            });
        }
    } catch (error) {
        console.error('Auto System Status API Error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to get system status'
        });
    }
});

// Force Backup API
router.post('/api/auto-system/force-backup', (req, res) => {
    try {
        if (global.autoSystemManager) {
            global.autoSystemManager.forceBackup();
            res.json({
                success: true,
                message: 'Forced backup initiated successfully'
            });
        } else {
            res.status(503).json({
                success: false,
                error: 'Auto System Manager not available'
            });
        }
    } catch (error) {
        console.error('Force Backup API Error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to initiate backup'
        });
    }
});

// Force Repair API
router.post('/api/auto-system/force-repair', (req, res) => {
    try {
        if (global.autoSystemManager) {
            global.autoSystemManager.forceRepair();
            res.json({
                success: true,
                message: 'Forced repair initiated successfully'
            });
        } else {
            res.status(503).json({
                success: false,
                error: 'Auto System Manager not available'
            });
        }
    } catch (error) {
        console.error('Force Repair API Error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to initiate repair'
        });
    }
});

// Force Optimization API
router.post('/api/auto-system/force-optimization', (req, res) => {
    try {
        if (global.autoSystemManager) {
            global.autoSystemManager.forceOptimization();
            res.json({
                success: true,
                message: 'Forced optimization initiated successfully'
            });
        } else {
            res.status(503).json({
                success: false,
                error: 'Auto System Manager not available'
            });
        }
    } catch (error) {
        console.error('Force Optimization API Error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to initiate optimization'
        });
    }
});

// System Health Check API
router.get('/api/auto-system/health', (req, res) => {
    try {
        if (global.autoSystemManager) {
            const health = global.autoSystemManager.getSystemHealth();
            res.json({
                success: true,
                health: health,
                timestamp: new Date().toISOString()
            });
        } else {
            res.status(503).json({
                success: false,
                error: 'Auto System Manager not available'
            });
        }
    } catch (error) {
        console.error('Health Check API Error:', error);
        res.status(500).json({
            success: false,
            error: 'Health check failed'
        });
    }
});

// Auto System Dashboard API
router.get('/api/auto-system/dashboard', (req, res) => {
    try {
        if (global.autoSystemManager) {
            const status = global.autoSystemManager.getSystemStatus();
            const health = global.autoSystemManager.getSystemHealth();
            
            res.json({
                success: true,
                dashboard: {
                    systemStatus: status,
                    systemHealth: health,
                    features: {
                        automaticPackageManagement: true,
                        automaticBackups: true,
                        websiteMonitoring: true,
                        autoRepair: true,
                        performanceOptimization: true
                    },
                    lastUpdate: new Date().toISOString()
                }
            });
        } else {
            res.status(503).json({
                success: false,
                error: 'Auto System Manager not available'
            });
        }
    } catch (error) {
        console.error('Dashboard API Error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to load dashboard'
        });
    }
});

module.exports = router;
