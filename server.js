const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const mongoose = require('mongoose');

// Load environment variables if .env file exists
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Enable CORS and JSON parsing
app.use(cors());
app.use(express.json());

// Serve static assets from root
app.use(express.static(__dirname));

// Admin Credentials
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'kaushal_admin';

// Simple in-memory session token store to validate auth
let activeSessions = new Set();

// -------------------------------------------------------------
// DATABASE SETUP (MongoDB with fallback to local JSON file)
// -------------------------------------------------------------
let isMongoConnected = false;
let BlogModel;

const MONGODB_URI = process.env.MONGODB_URI || process.env.MONGO_URI;

if (MONGODB_URI) {
    console.log('Attempting to connect to MongoDB Atlas...');
    mongoose.connect(MONGODB_URI, {
        useNewUrlParser: true,
        useUnifiedTopology: true
    })
    .then(() => {
        console.log('Successfully connected to MongoDB Atlas.');
        isMongoConnected = true;
        
        // Define Blog Mongoose Schema
        const blogSchema = new mongoose.Schema({
            title: { type: String, required: true },
            category: { type: String, required: true },
            date: { type: String, required: true },
            excerpt: { type: String, required: true },
            content: { type: String, required: true }
        }, { timestamps: true });
        
        // Convert virtual id
        blogSchema.virtual('id').get(function() {
            return this._id.toHexString();
        });
        blogSchema.set('toJSON', { virtuals: true });
        
        BlogModel = mongoose.model('Blog', blogSchema);
        
        // Seed default blogs to MongoDB if it is empty
        seedMongoDB();
    })
    .catch(err => {
        console.error('MongoDB connection error. Falling back to local file storage.', err);
        isMongoConnected = false;
    });
} else {
    console.log('No MONGODB_URI found. Initializing with local JSON file storage (blogs.json).');
}

// Seed local file data to MongoDB
async function seedMongoDB() {
    try {
        const count = await BlogModel.countDocuments();
        if (count === 0) {
            console.log('MongoDB collection is empty. Seeding initial data from blogs.json...');
            const localFile = path.join(__dirname, 'blogs.json');
            if (fs.existsSync(localFile)) {
                const data = JSON.parse(fs.readFileSync(localFile, 'utf8'));
                const formatted = data.map(item => ({
                    title: item.title,
                    category: item.category,
                    date: item.date,
                    excerpt: item.excerpt,
                    content: item.content
                }));
                await BlogModel.insertMany(formatted);
                console.log('MongoDB successfully seeded with initial posts.');
            }
        }
    } catch (e) {
        console.error('Error seeding MongoDB:', e);
    }
}

// Local File Helper Functions
const LOCAL_JSON_FILE = path.join(__dirname, 'blogs.json');

function readLocalBlogs() {
    try {
        if (!fs.existsSync(LOCAL_JSON_FILE)) {
            fs.writeFileSync(LOCAL_JSON_FILE, JSON.stringify([], null, 2));
            return [];
        }
        const raw = fs.readFileSync(LOCAL_JSON_FILE, 'utf8');
        return JSON.parse(raw);
    } catch (err) {
        console.error('Error reading blogs.json:', err);
        return [];
    }
}

function writeLocalBlogs(blogs) {
    try {
        fs.writeFileSync(LOCAL_JSON_FILE, JSON.stringify(blogs, null, 2));
        return true;
    } catch (err) {
        console.error('Error writing to blogs.json:', err);
        return false;
    }
}

// -------------------------------------------------------------
// AUTH MIDDLEWARE
// -------------------------------------------------------------
function authenticateAdmin(req, res, next) {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.split(' ')[1];
        if (activeSessions.has(token)) {
            return next();
        }
    }
    return res.status(401).json({ success: false, error: 'Unauthorized administrative token' });
}

// -------------------------------------------------------------
// API ENDPOINTS
// -------------------------------------------------------------

// Admin Login
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
        const token = 'session_' + Math.random().toString(36).substr(2) + Math.random().toString(36).substr(2);
        activeSessions.add(token);
        return res.json({ success: true, token });
    }
    return res.status(401).json({ success: false, error: 'Invalid admin credentials' });
});

// Admin Logout
app.post('/api/logout', (req, res) => {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.split(' ')[1];
        activeSessions.delete(token);
    }
    res.json({ success: true });
});

// Validate Token
app.get('/api/validate-token', (req, res) => {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.split(' ')[1];
        if (activeSessions.has(token)) {
            return res.json({ valid: true });
        }
    }
    res.json({ valid: false });
});

// Get all blogs
app.get('/api/blogs', async (req, res) => {
    try {
        if (isMongoConnected) {
            const dbBlogs = await BlogModel.find().sort({ createdAt: -1 });
            return res.json(dbBlogs);
        } else {
            const localBlogs = readLocalBlogs();
            // Return reverse order to show newest posts first
            return res.json([...localBlogs].reverse());
        }
    } catch (err) {
        console.error('Error fetching blogs:', err);
        res.status(500).json({ success: false, error: 'Failed to retrieve blog posts' });
    }
});

// Add a new blog
app.post('/api/blogs', authenticateAdmin, async (req, res) => {
    try {
        const { title, category, excerpt, content } = req.body;
        if (!title || !category || !excerpt || !content) {
            return res.status(400).json({ success: false, error: 'All fields (title, category, excerpt, content) are required.' });
        }

        const dateOptions = { year: 'numeric', month: 'long', day: 'numeric' };
        const currentDate = new Date().toLocaleDateString('en-US', dateOptions);

        if (isMongoConnected) {
            const newBlog = new BlogModel({
                title,
                category,
                date: currentDate,
                excerpt,
                content
            });
            await newBlog.save();
            return res.status(201).json({ success: true, blog: newBlog });
        } else {
            const blogs = readLocalBlogs();
            const newId = String(Date.now());
            const newBlog = {
                id: newId,
                title,
                category,
                date: currentDate,
                excerpt,
                content
            };
            blogs.push(newBlog);
            writeLocalBlogs(blogs);
            return res.status(201).json({ success: true, blog: newBlog });
        }
    } catch (err) {
        console.error('Error creating blog:', err);
        res.status(500).json({ success: false, error: 'Failed to create blog post' });
    }
});

// Delete a blog
app.delete('/api/blogs/:id', authenticateAdmin, async (req, res) => {
    try {
        const id = req.params.id;
        if (isMongoConnected) {
            const deleted = await BlogModel.findByIdAndDelete(id);
            if (!deleted) {
                return res.status(404).json({ success: false, error: 'Blog post not found in MongoDB database' });
            }
            return res.json({ success: true, message: 'Blog post successfully deleted from MongoDB.' });
        } else {
            const blogs = readLocalBlogs();
            const filtered = blogs.filter(blog => blog.id !== id);
            if (blogs.length === filtered.length) {
                return res.status(404).json({ success: false, error: 'Blog post not found in local file storage' });
            }
            writeLocalBlogs(filtered);
            return res.json({ success: true, message: 'Blog post successfully deleted from local files.' });
        }
    } catch (err) {
        console.error('Error deleting blog:', err);
        res.status(500).json({ success: false, error: 'Failed to delete blog post' });
    }
});

// Primary route to serve portfolio
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Start Server
app.listen(PORT, () => {
    console.log(`=================================================`);
    console.log(` PORTFOLIO APP SERVER LAUNCHED SUCCESSFULLY`);
    console.log(` Running locally at: http://localhost:${PORT}`);
    console.log(` Admin Dashboard:    http://localhost:${PORT}/admin.html`);
    console.log(`=================================================`);
});
