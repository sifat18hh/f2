const fs = require('fs');
const path = require('path');

class ObjectStorageManager {
    constructor() {
        this.isEnabled = false;
        this.storage = null;
        this.bucketName = 'tubeclone-videos'; // Default bucket name
        this.storageType = 'file-system'; // Fallback to file system
        this.initialize();
    }

    async initialize() {
        try {
            // Use file system storage as primary method for Replit
            this.bucketName = process.env.REPL_SLUG || 'tubeclone-storage';
            this.storageType = 'replit-filesystem';
            this.isEnabled = true;

            // Ensure uploads directory exists
            const fs = require('fs');
            if (!fs.existsSync('uploads')) {
                fs.mkdirSync('uploads', { recursive: true });
            }

            console.log('✅ Object Storage initialized with Replit file system');
            console.log(`📁 Storage bucket: ${this.bucketName}`);
        } catch (error) {
            console.warn('⚠️ Object Storage initialization failed, using fallback:', error.message);
            this.isEnabled = true; // Still enable with fallback
            this.storageType = 'fallback';
        }
    }

    async uploadVideo(filePath, originalName) {
        try {
            const fs = require('fs');
            const path = require('path');

            // Ensure uploads directory exists
            if (!fs.existsSync('uploads')) {
                fs.mkdirSync('uploads', { recursive: true });
            }

            // Generate unique filename
            const fileName = `video_${Date.now()}_${path.basename(originalName)}`;
            const uploadPath = path.join('uploads', fileName);

            // Copy file to uploads directory
            if (fs.existsSync(filePath)) {
                fs.copyFileSync(filePath, uploadPath);

                // Clean up original temp file if different
                if (filePath !== uploadPath) {
                    try {
                        fs.unlinkSync(filePath);
                    } catch (cleanupError) {
                        console.warn('Could not clean up temp file:', cleanupError.message);
                    }
                }
            } else {
                throw new Error('Source file not found');
            }

            const fileSize = fs.statSync(uploadPath).size;

            return {
                success: true,
                fileName: fileName,
                url: `/uploads/${fileName}`,
                storageType: this.storageType,
                size: fileSize,
                bucket: this.bucketName
            };
        } catch (error) {
            console.error('Video upload error:', error);
            return {
                success: false,
                error: error.message
            };
        }
    }

    setupObjectStorageClient() {
        if (!this.enabled) return;

        try {
            // Check if we're in Replit environment with Object Storage
            if (process.env.REPLIT_DB_URL) {
                // Try to import Replit Object Storage client
                const { Client } = require('@replit/object-storage');
                this.client = new Client();

                // Get default bucket with proper error handling
                try {
                    this.bucket = this.client.getBucket();
                    console.log('🪣 Connected to Replit Object Storage bucket');
                } catch (bucketError) {
                    console.log('⚠️ Bucket access failed, using simulated storage');
                    this.setupSimulatedStorage();
                    return;
                }
            } else {
                // Not in Replit environment
                console.log('📦 Not in Replit environment, using simulated Object Storage');
                this.setupSimulatedStorage();
            }

        } catch (error) {
            console.log('📦 Object Storage client failed, using simulated storage:', error.message);
            this.setupSimulatedStorage();
        }
    }

    setupSimulatedStorage() {
        // Create simulated object storage structure for development
        const objectStorageDir = './object_storage_simulation';
        if (!fs.existsSync(objectStorageDir)) {
            fs.mkdirSync(objectStorageDir, { recursive: true });
        }

        this.simulatedStoragePath = objectStorageDir;
        console.log('🔄 Simulated Object Storage ready');
    }

    async uploadToReplitStorage(fileName, fileBuffer) {
        try {
            // Check if client and bucket are available
            if (!this.client || !this.bucket) {
                throw new Error('Object Storage client not properly initialized');
            }

            // Upload to Replit Object Storage with bucket check
            await this.bucket.uploadFromBytes(fileName, fileBuffer);

            // Store metadata
            const metadata = {
                fileName: fileName,
                uploadDate: new Date().toISOString(),
                size: fileBuffer.length,
                type: 'video'
            };

            try {
                await this.bucket.uploadFromText(`metadata/${fileName}.json`, JSON.stringify(metadata));
            } catch (metaError) {
                console.warn('Metadata upload failed:', metaError.message);
                // Continue without metadata if main upload succeeded
            }

        } catch (error) {
            console.error('Object Storage upload error:', error.message);
            // Fall back to simulated storage
            this.setupSimulatedStorage();
            throw new Error('Object Storage upload failed, falling back to local storage');
        }
    }

    async uploadToSimulatedStorage(fileName, fileBuffer) {
        const filePath = path.join(this.simulatedStoragePath, fileName);
        fs.writeFileSync(filePath, fileBuffer);

        // Store metadata
        const metadataPath = path.join(this.simulatedStoragePath, 'metadata');
        if (!fs.existsSync(metadataPath)) {
            fs.mkdirSync(metadataPath);
        }

        const metadata = {
            fileName: fileName,
            uploadDate: new Date().toISOString(),
            size: fileBuffer.length,
            type: 'video'
        };

        fs.writeFileSync(
            path.join(metadataPath, `${fileName}.json`),
            JSON.stringify(metadata, null, 2)
        );
    }

    async getVideo(fileName) {
        try {
            if (this.client && this.bucket && this.enabled) {
                // Get from Replit Object Storage
                try {
                    const videoBuffer = await this.bucket.downloadAsBytes(fileName);
                    return videoBuffer;
                } catch (downloadError) {
                    console.warn('Object Storage download failed:', downloadError.message);
                    // Fall back to simulated storage
                }
            }

            // Get from simulated storage
            if (this.simulatedStoragePath) {
                const filePath = path.join(this.simulatedStoragePath, fileName);
                if (fs.existsSync(filePath)) {
                    return fs.readFileSync(filePath);
                }
            }

            throw new Error('Video not found in any storage');

        } catch (error) {
            console.error('❌ Video retrieval failed:', error.message);
            return null;
        }
    }

    async deleteVideo(fileName) {
        try {
            if (this.client && this.enabled) {
                // Delete from Replit Object Storage
                await this.client.delete(fileName);
                await this.client.delete(`metadata/${fileName}.json`);
            } else {
                // Delete from simulated storage
                const filePath = path.join(this.simulatedStoragePath, fileName);
                const metadataPath = path.join(this.simulatedStoragePath, 'metadata', `${fileName}.json`);

                if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
                if (fs.existsSync(metadataPath)) fs.unlinkSync(metadataPath);
            }

            console.log(`🗑️ Video deleted: ${fileName}`);
            return true;

        } catch (error) {
            console.error('❌ Video deletion failed:', error.message);
            return false;
        }
    }

    generateUniqueFileName(originalName) {
        const timestamp = Date.now();
        const random = Math.random().toString(36).substring(2);
        const extension = path.extname(originalName);
        return `video_${timestamp}_${random}${extension}`;
    }

    getVideoUrl(fileName) {
        if (this.enabled) {
            return `/api/object-storage/video/${fileName}`;
        } else {
            return `/api/simulated-storage/video/${fileName}`;
        }
    }

    async listVideos() {
        try {
            const videos = [];

            if (this.client && this.enabled) {
                // List from Object Storage (simplified)
                console.log('📋 Listing videos from Object Storage...');
                // Note: Real implementation would use object listing APIs
            } else {
                // List from simulated storage
                if (fs.existsSync(this.simulatedStoragePath)) {
                    const files = fs.readdirSync(this.simulatedStoragePath);
                    files.forEach(file => {
                        if (file.startsWith('video_') && !file.endsWith('.json')) {
                            videos.push({
                                fileName: file,
                                url: this.getVideoUrl(file)
                            });
                        }
                    });
                }
            }

            return videos;

        } catch (error) {
            console.error('❌ Video listing failed:', error.message);
            return [];
        }
    }

    async getStorageInfo() {
        const info = {
            enabled: this.enabled,
            type: this.enabled ? 'Replit Object Storage' : 'Simulated Storage',
            unlimited: this.enabled,
            githubSafe: true,
            videoCount: 0,
            totalSize: '0 MB'
        };

        try {
            const videos = await this.listVideos();
            info.videoCount = videos.length;

            if (!this.enabled && fs.existsSync(this.simulatedStoragePath)) {
                let totalSize = 0;
                const files = fs.readdirSync(this.simulatedStoragePath);
                files.forEach(file => {
                    const filePath = path.join(this.simulatedStoragePath, file);
                    const stats = fs.statSync(filePath);
                    totalSize += stats.size;
                });
                info.totalSize = this.formatFileSize(totalSize);
            }
        } catch (error) {
            console.error('Error getting storage info:', error);
        }

        return info;
    }

    formatFileSize(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
}

module.exports = ObjectStorageManager;