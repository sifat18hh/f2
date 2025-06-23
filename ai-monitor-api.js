
const express = require('express');
const router = express.Router();

// AI Monitor Status API
router.get('/api/ai-monitor/status', (req, res) => {
    try {
        if (global.advancedAIMonitor) {
            const status = global.advancedAIMonitor.getSystemStatus();
            res.json({
                success: true,
                status: status,
                timestamp: new Date().toISOString()
            });
        } else {
            res.status(503).json({
                success: false,
                error: 'AI Monitor not initialized'
            });
        }
    } catch (error) {
        console.error('AI Monitor Status API Error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to get AI monitor status'
        });
    }
});

// AI Diagnostic Report API
router.get('/api/ai-monitor/diagnostics', (req, res) => {
    try {
        if (global.advancedAIMonitor) {
            const report = global.advancedAIMonitor.getDiagnosticReport();
            res.json({
                success: true,
                report: report,
                timestamp: new Date().toISOString()
            });
        } else {
            res.status(503).json({
                success: false,
                error: 'AI Monitor not available'
            });
        }
    } catch (error) {
        console.error('AI Diagnostics API Error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to get diagnostic report'
        });
    }
});

// Force AI System Check API
router.post('/api/ai-monitor/force-check', async (req, res) => {
    try {
        if (global.advancedAIMonitor) {
            await global.advancedAIMonitor.performComprehensiveCheck();
            res.json({
                success: true,
                message: 'AI comprehensive check initiated successfully'
            });
        } else {
            res.status(503).json({
                success: false,
                error: 'AI Monitor not available'
            });
        }
    } catch (error) {
        console.error('Force AI Check API Error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to initiate AI check'
        });
    }
});

// AI Error Detection API
router.post('/api/ai-monitor/detect-errors', async (req, res) => {
    try {
        if (global.advancedAIMonitor) {
            const errors = await global.advancedAIMonitor.detectAndDiagnoseErrors();
            res.json({
                success: true,
                errors: errors,
                message: 'AI error detection completed'
            });
        } else {
            res.status(503).json({
                success: false,
                error: 'AI Monitor not available'
            });
        }
    } catch (error) {
        console.error('AI Error Detection API Error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to detect errors'
        });
    }
});

// AI Performance Optimization API
router.post('/api/ai-monitor/optimize', async (req, res) => {
    try {
        if (global.advancedAIMonitor) {
            await global.advancedAIMonitor.autoOptimizePerformance();
            res.json({
                success: true,
                message: 'AI performance optimization completed'
            });
        } else {
            res.status(503).json({
                success: false,
                error: 'AI Monitor not available'
            });
        }
    } catch (error) {
        console.error('AI Optimization API Error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to optimize performance'
        });
    }
});

// AI System Health API
router.get('/api/ai-monitor/health', (req, res) => {
    try {
        if (global.advancedAIMonitor) {
            const health = global.advancedAIMonitor.systemHealth;
            res.json({
                success: true,
                health: health,
                isHealthy: Object.values(health).every(status => 
                    status.status !== 'error' && status.status !== 'critical'
                ),
                timestamp: new Date().toISOString()
            });
        } else {
            res.status(503).json({
                success: false,
                error: 'AI Monitor not available'
            });
        }
    } catch (error) {
        console.error('AI Health API Error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to get system health'
        });
    }
});

module.exports = router;
