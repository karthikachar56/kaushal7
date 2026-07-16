const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const mongoose = require('mongoose');
const multer = require('multer');
const crypto = require('crypto');

// Load environment variables if .env file exists
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Enable CORS and JSON parsing
app.use(cors());
app.use(express.json());

// Serve static files from root directory (essential for local run)
app.use(express.static(path.join(__dirname, '..')));

// Admin credentials
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'kaushal_admin';
const JWT_SECRET = process.env.JWT_SECRET || 'kaushal_secret_key_987654321_portfolio';

// Stateless JWT Helper Functions (Node.js crypto implementation)
function generateToken(payload) {
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
    const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const signature = crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${body}`).digest('base64url');
    return `${header}.${body}.${signature}`;
}

function verifyToken(token) {
    try {
        const parts = token.split('.');
        if (parts.length !== 3) return null;
        const [header, body, signature] = parts;
        const expectedSignature = crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${body}`).digest('base64url');
        if (signature !== expectedSignature) return null;
        
        const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
        if (payload.exp && Date.now() > payload.exp) {
            return null; // Token expired
        }
        return payload;
    } catch (e) {
        return null;
    }
}

// -------------------------------------------------------------
// DATABASE SETUP & CACHING FOR VERCEL SERVERLESS FUNCTIONS
// -------------------------------------------------------------
let cachedDb = null;
let isSeeded = false;

// Dynamic model retrieval to prevent OverwriteModelError in serverless hot reloads
const getBlogModel = () => {
    const blogSchema = new mongoose.Schema({
        title: { type: String, required: true },
        category: { type: String, required: true },
        date: { type: String, required: true },
        excerpt: { type: String, required: true },
        content: { type: String, required: true },
        imageUrl: { type: String, default: '' }
    }, { timestamps: true });

    blogSchema.virtual('id').get(function() {
        return this._id.toHexString();
    });
    blogSchema.set('toJSON', { virtuals: true });

    return mongoose.models.Blog || mongoose.model('Blog', blogSchema);
};

const getImageModel = () => {
    const imageSchema = new mongoose.Schema({
        filename: { type: String, required: true, unique: true },
        contentType: { type: String, required: true },
        data: { type: Buffer, required: true }
    }, { timestamps: true });

    return mongoose.models.Image || mongoose.model('Image', imageSchema);
};

// Cached connection function
async function connectToDatabase() {
    if (cachedDb) {
        return cachedDb;
    }
    const uri = process.env.MONGODB_URI;
    if (!uri) {
        throw new Error('MONGODB_URI environment variable is not defined.');
    }
    const db = await mongoose.connect(uri, {
        useNewUrlParser: true,
        useUnifiedTopology: true
    });
    cachedDb = db;
    
    // Seed database if it's empty
    if (!isSeeded) {
        isSeeded = true;
        await seedMongoDB();
    }
    
    return db;
}

// Seed local blogs.json to MongoDB
async function seedMongoDB() {
    try {
        const BlogModel = getBlogModel();
        const count = await BlogModel.countDocuments();
        if (count === 0) {
            console.log('MongoDB collection is empty. Seeding initial data from blogs.json...');
            const localFile = path.join(__dirname, '../blogs.json');
            if (fs.existsSync(localFile)) {
                const data = JSON.parse(fs.readFileSync(localFile, 'utf8'));
                const formatted = data.map(item => ({
                    title: item.title,
                    category: item.category,
                    date: item.date,
                    excerpt: item.excerpt,
                    content: item.content,
                    imageUrl: item.imageUrl || ''
                }));
                await BlogModel.insertMany(formatted);
                console.log('MongoDB successfully seeded with initial posts.');
            }
        }
    } catch (e) {
        console.error('Error seeding MongoDB:', e);
    }
}

// Database connection middleware for every incoming request
app.use(async (req, res, next) => {
    try {
        await connectToDatabase();
        next();
    } catch (err) {
        console.error('Database connection failed:', err);
        res.status(500).json({ success: false, error: 'Internal server error: Database offline.' });
    }
});

// -------------------------------------------------------------
// FILE UPLOAD CONFIGURATION (Memory Storage for Vercel stability)
// -------------------------------------------------------------
const storage = multer.memoryStorage();
const upload = multer({
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
    fileFilter: (req, file, cb) => {
        const filetypes = /jpeg|jpg|png|gif|webp/;
        const mimetype = filetypes.test(file.mimetype);
        const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
        if (mimetype && extname) {
            return cb(null, true);
        }
        cb(new Error('Only image files (jpg, jpeg, png, gif, webp) are allowed!'));
    }
});

// -------------------------------------------------------------
// AUTH MIDDLEWARE
// -------------------------------------------------------------
function authenticateAdmin(req, res, next) {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.split(' ')[1];
        const decoded = verifyToken(token);
        if (decoded && decoded.role === 'admin') {
            req.adminUser = decoded;
            return next();
        }
    }
    return res.status(401).json({ success: false, error: 'Unauthorized administrative access.' });
}

// -------------------------------------------------------------
// API ENDPOINTS
// -------------------------------------------------------------

// Admin Login
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
        const payload = { username, role: 'admin', exp: Date.now() + 24 * 60 * 60 * 1000 }; // 24 hours
        const token = generateToken(payload);
        return res.json({ success: true, token });
    }
    return res.status(401).json({ success: false, error: 'Invalid admin credentials' });
});

// Admin Logout (Stateless success response)
app.post('/api/logout', (req, res) => {
    res.json({ success: true });
});

// Validate Token
app.get('/api/validate-token', (req, res) => {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.split(' ')[1];
        const decoded = verifyToken(token);
        if (decoded && decoded.role === 'admin') {
            return res.json({ valid: true });
        }
    }
    res.json({ valid: false });
});

// Get all blogs
app.get('/api/blogs', async (req, res) => {
    try {
        const BlogModel = getBlogModel();
        const dbBlogs = await BlogModel.find().sort({ createdAt: -1 });
        // Map elements to virtual structure
        const formatted = dbBlogs.map(blog => {
            const obj = blog.toObject({ virtuals: true });
            obj.id = obj._id.toString();
            return obj;
        });
        return res.json(formatted);
    } catch (err) {
        console.error('Error fetching blogs:', err);
        res.status(500).json({ success: false, error: 'Failed to retrieve blog posts' });
    }
});

// Add new blog
app.post('/api/blogs', authenticateAdmin, async (req, res) => {
    try {
        const { title, category, excerpt, content, imageUrl } = req.body;
        if (!title || !category || !excerpt || !content) {
            return res.status(400).json({ success: false, error: 'All fields (title, category, excerpt, content) are required.' });
        }

        const dateOptions = { year: 'numeric', month: 'long', day: 'numeric' };
        const currentDate = new Date().toLocaleDateString('en-US', dateOptions);

        const BlogModel = getBlogModel();
        const newBlog = new BlogModel({
            title,
            category,
            date: currentDate,
            excerpt,
            content,
            imageUrl: imageUrl || ''
        });
        await newBlog.save();
        
        const obj = newBlog.toObject({ virtuals: true });
        obj.id = obj._id.toString();
        return res.status(201).json({ success: true, blog: obj });
    } catch (err) {
        console.error('Error creating blog:', err);
        res.status(500).json({ success: false, error: 'Failed to create blog post' });
    }
});

// Image Upload Endpoint (Uses MemoryStorage and saves to MongoDB)
app.post('/api/upload', authenticateAdmin, (req, res) => {
    upload.single('image')(req, res, async (err) => {
        if (err) {
            return res.status(400).json({ success: false, error: err.message });
        }
        if (!req.file) {
            return res.status(400).json({ success: false, error: 'No file selected' });
        }
        
        try {
            const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
            const filename = uniqueSuffix + path.extname(req.file.originalname);
            
            const ImageModel = getImageModel();
            const newImage = new ImageModel({
                filename: filename,
                contentType: req.file.mimetype,
                data: req.file.buffer
            });
            await newImage.save();
            
            // Return URL mapped to our rewrite routes
            const fileUrl = `/uploads/${filename}`;
            return res.json({ success: true, url: fileUrl });
        } catch (dbErr) {
            console.error('Database image upload error:', dbErr);
            return res.status(500).json({ success: false, error: 'Failed to save image to database.' });
        }
    });
});

// Serve images dynamically from MongoDB (with disk fallback for pre-existing assets)
app.get('/uploads/:filename', async (req, res) => {
    try {
        const ImageModel = getImageModel();
        const file = await ImageModel.findOne({ filename: req.params.filename });
        
        if (file) {
            res.setHeader('Content-Type', file.contentType);
            res.setHeader('Cache-Control', 'public, max-age=31536000, immutable'); // Cache for 1 year
            return res.send(file.data);
        }
        
        // Fallback to local filesystem
        const localPath = path.join(__dirname, '../uploads', req.params.filename);
        if (fs.existsSync(localPath)) {
            const ext = path.extname(req.params.filename).toLowerCase();
            let contentType = 'image/jpeg';
            if (ext === '.png') contentType = 'image/png';
            else if (ext === '.gif') contentType = 'image/gif';
            else if (ext === '.webp') contentType = 'image/webp';
            
            res.setHeader('Content-Type', contentType);
            res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
            return res.sendFile(localPath);
        }
        
        return res.status(404).send('Not Found');
    } catch (err) {
        console.error('Error loading image:', err);
        return res.status(500).send('Error loading image.');
    }
});

// Delete blog post
app.delete('/api/blogs/:id', authenticateAdmin, async (req, res) => {
    try {
        const BlogModel = getBlogModel();
        const deleted = await BlogModel.findByIdAndDelete(req.params.id);
        if (!deleted) {
            return res.status(404).json({ success: false, error: 'Blog post not found.' });
        }
        return res.json({ success: true, message: 'Blog post successfully deleted.' });
    } catch (err) {
        console.error('Error deleting blog:', err);
        res.status(500).json({ success: false, error: 'Failed to delete blog post' });
    }
});

// Export the Express app for Vercel Serverless Functions
module.exports = app;

// Start local server if not running inside the Vercel platform environment
if (!process.env.VERCEL) {
    app.listen(PORT, () => {
        console.log(`=================================================`);
        console.log(` PORTFOLIO APP SERVER LAUNCHED SUCCESSFULLY`);
        console.log(` Running locally at: http://localhost:${PORT}`);
        console.log(` Admin Dashboard:    http://localhost:${PORT}/admin.html`);
        console.log(`=================================================`);
    });
}
