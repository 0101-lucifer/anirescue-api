const express = require('express');
const cors = require('cors');
const path = require('path');
const multer = require('multer');
require('dotenv').config();
const { Pool } = require('pg');

// Security & Optimization Imports
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const compression = require('compression'); 
const NodeCache = require('node-cache');    

const app = express();
const port = process.env.PORT || 3000;

const apiCache = new NodeCache({ stdTTL: 15 });

// --- SECURITY & OPTIMIZATION MIDDLEWARES ---
app.use(helmet()); 
app.use(cors()); 

// 1. SECURE JSON PARSER: Reverted to 2mb to protect RAM
app.use(express.json({ limit: '2mb' })); 
app.use(express.urlencoded({ limit: '2mb', extended: true }));
app.use(compression()); 

// 2. EXPOSE UPLOADS: Allow React to fetch the saved images
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// 3. MULTER CONFIGURATION: Stream files directly to disk
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/'); 
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, 'rescue-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({ 
  storage: storage,
  limits: { fileSize: 15 * 1024 * 1024 } // 15MB hard limit
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, 
  max: 10, 
  message: { error: 'Too many authentication attempts. Please try again later.' }
});

// --- DATABASE CONNECTION ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

pool.connect((err, client, release) => {
  if (err) return console.error('Error acquiring client', err.stack);
  console.log('✅ Successfully connected to Neon PostgreSQL Database');
  release();
});

// --- JWT VERIFICATION MIDDLEWARE ---
const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Access Denied. No token provided.' });

  const token = authHeader.split(' ')[1];
  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = verified; 
    next();
  } catch (err) {
    res.status(400).json({ error: 'Invalid Token' });
  }
};

// --- AUTHENTICATION ROUTES ---
app.post('/api/auth/register', authLimiter, async (req, res) => {
  const { name, email, password } = req.body;
  try {
    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    const result = await pool.query(
      'INSERT INTO users (full_name, email, password_hash) VALUES ($1, $2, $3) RETURNING id, full_name, email, role',
      [name, email, passwordHash] 
    );
    
    const user = result.rows[0];
    const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '30d' });

    res.json({ token, user });
  } catch (err) {
    if (err.code === '23505') return res.status(400).json({ error: 'Email already exists' });
    res.status(500).json({ error: 'Server error during registration' });
  }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Not registered' }); 
    
    const user = result.rows[0];
    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    if (!isValidPassword) return res.status(401).json({ error: 'Incorrect password' }); 

    const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '30d' });
    delete user.password_hash;
    res.json({ token, user });
  } catch (err) {
    res.status(500).json({ error: 'Server error during login' });
  }
});

app.get('/api/auth/me', verifyToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, full_name, email, role FROM users WHERE id = $1', [req.user.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    res.json({ user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'Server error during authentication check' });
  }
});

// --- RESCUE DISPATCH ROUTES ---
// 4. UPDATED RESCUE ROUTE: Uses multer's upload.single('image')
app.post('/api/cases/report', verifyToken, upload.single('image'), async (req, res) => {
  try {
    const { location, description } = req.body;
    const parsedLocation = JSON.parse(location); 
    const reporterId = req.user.id;
    
    if (!req.file) {
      return res.status(400).json({ error: 'Please upload an image.' });
    }

    const imagePath = `/uploads/${req.file.filename}`;

    const lat = parsedLocation.lat || null;
    const lng = parsedLocation.lng || null;
    const manualAddress = parsedLocation.address || null;
    const isCustom = parsedLocation.isCustom || parsedLocation.isManual || false;

    const result = await pool.query(
      `INSERT INTO rescue_cases (issue_description, latitude, longitude, manual_address, is_custom_location, image_payload, reporter_id) 
      VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, status`,
      [description, lat, lng, manualAddress, isCustom, imagePath, reporterId]
    );
    
    apiCache.flushAll(); 
    
    res.json({ success: true, case: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to submit rescue case' });
  }
});

app.get('/api/cases/map', async (req, res) => {
  try {
    if (apiCache.has('map_data')) return res.json(apiCache.get('map_data'));

    const result = await pool.query(
      `SELECT id, species, issue_description, priority, latitude, longitude 
       FROM rescue_cases WHERE status != 'Resolved' AND latitude IS NOT NULL AND longitude IS NOT NULL`
    );
    
    apiCache.set('map_data', result.rows);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch map data' });
  }
});

app.get('/api/cases', verifyToken, async (req, res) => {
  try {
    if (apiCache.has('dashboard_data')) return res.json(apiCache.get('dashboard_data'));

    const result = await pool.query(
      `SELECT id, species, issue_description, priority, status, manual_address, latitude, longitude, assigned_volunteer_id, created_at 
       FROM rescue_cases ORDER BY created_at DESC LIMIT 50`
    );

    apiCache.set('dashboard_data', result.rows);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch cases' });
  }
});

app.put('/api/cases/:id/status', verifyToken, async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;
  const volunteerId = req.user.id; 

  try {
    let query = '';
    let params = [];

    if (status === 'Active') {
      query = `UPDATE rescue_cases SET status = $1, assigned_volunteer_id = $2 WHERE id = $3 AND (status = 'Unassigned' OR status = 'Pending') RETURNING *`;
      params = [status, volunteerId, id];
    } else if (status === 'Resolved') {
      query = `UPDATE rescue_cases SET status = $1 WHERE id = $2 AND assigned_volunteer_id = $3 RETURNING *`;
      params = [status, id, volunteerId];
    } else {
      return res.status(400).json({ error: 'Invalid status update' });
    }

    const result = await pool.query(query, params);
    if (result.rows.length === 0) return res.status(403).json({ error: 'Action denied' });

    apiCache.flushAll();
    res.json({ success: true, case: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update case status' });
  }
});

app.listen(port, () => console.log(`🚀 Secure API Gateway running on http://localhost:${port}`));