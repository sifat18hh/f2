
const express = require('express');
const router = express.Router();

// Serve video from Object Storage
router.get('/api/object-storage/video/:filename', async (req, res) => {
    try {
        const filename = req.params.filename;
        
        if (!global.objectStorage) {
            return res.status(503).json({ error: 'Object Storage not available' });
        }
        
        const videoBuffer = await global.objectStorage.getVideo(filename);
        
        if (!videoBuffer) {
            return res.status(404).json({ error: 'Video not found' });
        }
        
        // Set appropriate headers for video streaming
        res.setHeader('Content-Type', 'video/mp4');
        res.setHeader('Accept-Ranges', 'bytes');
        res.setHeader('Cache-Control', 'public, max-age=31536000');
        
        // Send video data
        res.send(videoBuffer);
        
    } catch (error) {
        console.error('Object Storage video serve error:', error);
        res.status(500).json({ error: 'Failed to serve video' });
    }
});

// Serve video from simulated storage (development)
router.get('/api/simulated-storage/video/:filename', async (req, res) => {
    try {
        const filename = req.params.filename;
        
        if (!global.objectStorage) {
            return res.status(503).json({ error: 'Storage not available' });
        }
        
        const videoBuffer = await global.objectStorage.getVideo(filename);
        
        if (!videoBuffer) {
            return res.status(404).json({ error: 'Video not found in simulated storage' });
        }
        
        // Set appropriate headers for video streaming
        res.setHeader('Content-Type', 'video/mp4');
        res.setHeader('Accept-Ranges', 'bytes');
        res.setHeader('Cache-Control', 'public, max-age=31536000');
        
        // Send video data
        res.send(videoBuffer);
        
    } catch (error) {
        console.error('Simulated storage video serve error:', error);
        res.status(500).json({ error: 'Failed to serve video' });
    }
});

// Delete video from Object Storage
router.delete('/api/object-storage/video/:filename', async (req, res) => {
    try {
        const filename = req.params.filename;
        
        if (!global.objectStorage) {
            return res.status(503).json({ error: 'Object Storage not available' });
        }
        
        const success = await global.objectStorage.deleteVideo(filename);
        
        if (success) {
            res.json({ success: true, message: 'Video deleted from Object Storage' });
        } else {
            res.status(500).json({ error: 'Failed to delete video' });
        }
        
    } catch (error) {
        console.error('Object Storage video delete error:', error);
        res.status(500).json({ error: 'Failed to delete video' });
    }
});

// Get Object Storage info
router.get('/api/object-storage/info', async (req, res) => {
    try {
        if (!global.objectStorage) {
            return res.status(503).json({ error: 'Object Storage not available' });
        }
        
        const info = await global.objectStorage.getStorageInfo();
        res.json({
            success: true,
            storage: info
        });
        
    } catch (error) {
        console.error('Object Storage info error:', error);
        res.status(500).json({ error: 'Failed to get storage info' });
    }
});

// List videos in Object Storage
router.get('/api/object-storage/videos', async (req, res) => {
    try {
        if (!global.objectStorage) {
            return res.status(503).json({ error: 'Object Storage not available' });
        }
        
        const videos = await global.objectStorage.listVideos();
        res.json({
            success: true,
            videos: videos
        });
        
    } catch (error) {
        console.error('Object Storage video list error:', error);
        res.status(500).json({ error: 'Failed to list videos' });
    }
});

module.exports = router;
