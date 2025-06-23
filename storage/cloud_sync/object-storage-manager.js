
const fs = require('fs');
const path = require('path');

class ObjectStorageManager {
    constructor() {
        this.enabled = false;
        this.bucketID = null;
        this.initialize();
    }

    async initialize() {
        try {
            // Check if Replit Object Storage is available
            this.checkObjectStorageAvailability();
            
            // Setup Object Storage client
            await this.setupObjectStorageClient();
            
            console.log('📦 Object Storage Manager initialized');
            console.log('🎥 Videos will be stored in Replit Object Storage');
            console.log('✅ No GitHub file size limits!');
            
        } catch (error) {
            console.log('⚠️ Object Storage not available, using local storage');
            this.enabled = false;
        }
    }

    checkObjectStorageAvailability() {
        // Check if running on Replit with Object Storage
        if (process.env.REPLIT_DB_URL || process.env.REPL_ID) {
            this.enabled = true;
            console.log('✅ Replit environment detected - Object Storage available');
        } else {
            console.log('ℹ️ Not on Replit - using local storage fallback');
            this.enabled = false;
        }
    }

    async setupObjectStorageClient() {
        if (!this.enabled) return;

        try {
            // Try to import Replit Object Storage client
            const { Client } = require('@replit/object-storage');
            this.client = new Client();
            
            // Get default bucket
            this.bucket = this.client.getBucket();
            console.log('🪣 Connected to Replit Object Storage bucket');
            
        } catch (error) {
            console.log('📦 Using simulated Object Storage for development');
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

    async uploadVideo(filePath, originalName) {
        try {
            if (!fs.existsSync(filePath)) {
                throw new Error('File not found: ' + filePath);
            }

            const fileName = this.generateUniqueFileName(originalName);
            const fileBuffer = fs.readFileSync(filePath);
            
            if (this.client && this.enabled) {
                // Upload to Replit Object Storage
                await this.uploadToReplitStorage(fileName, fileBuffer);
                console.log(`☁️ Video uploaded to Object Storage: ${fileName}`);
            } else {
                // Upload to simulated storage
                await this.uploadToSimulatedStorage(fileName, fileBuffer);
                console.log(`💾 Video uploaded to simulated storage: ${fileName}`);
            }

            // Delete local file to save GitHub space
            fs.unlinkSync(filePath);
            console.log(`🗑️ Local file deleted: ${filePath}`);

            return {
                success: true,
                fileName: fileName,
                storageType: this.enabled ? 'object-storage' : 'simulated',
                url: this.getVideoUrl(fileName)
            };

        } catch (error) {
            console.error('❌ Video upload failed:', error.message);
            return {
                success: false,
                error: error.message
            };
        }
    }

    async uploadToReplitStorage(fileName, fileBuffer) {
        try {
            // Upload to Replit Object Storage
            await this.client.uploadFromBytes(fileName, fileBuffer);
            
            // Store metadata
            const metadata = {
                fileName: fileName,
                uploadDate: new Date().toISOString(),
                size: fileBuffer.length,
                type: 'video'
            };
            
            await this.client.uploadFromText(`metadata/${fileName}.json`, JSON.stringify(metadata));
            
        } catch (error) {
            throw new Error('Object Storage upload failed: ' + error.message);
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
            if (this.client && this.enabled) {
                // Get from Replit Object Storage
                const videoBuffer = await this.client.downloadAsBytes(fileName);
                return videoBuffer;
            } else {
                // Get from simulated storage
                const filePath = path.join(this.simulatedStoragePath, fileName);
                if (fs.existsSync(filePath)) {
                    return fs.readFileSync(filePath);
                }
            }
            
            throw new Error('Video not found');
            
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
