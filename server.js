const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Database Connection
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/eloance';
const JWT_SECRET = process.env.JWT_SECRET || 'eloance_super_secret_key_2026';

mongoose.connect(MONGO_URI)
  .then(() => console.log('Connected to MongoDB Atlas successfully'))
  .catch(err => console.error('MongoDB connection error:', err));

// Mongoose Schemas & Models
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  phone: { type: String, required: true },
  password_hash: { type: String, required: true },
  role: { type: String, enum: ['user', 'technician', 'admin'], default: 'user' },
  approval_status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
}, { timestamps: true });

const serviceRequestSchema = new mongoose.Schema({
  ticket_number: { type: String, required: true, unique: true },
  user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  service_type: { type: String, required: true },
  device_details: { type: String, required: true },
  problem_description: { type: String, required: true },
  customer_latitude: { type: Number },
  customer_longitude: { type: Number },
  customer_address: { type: String },
  status: { type: String, default: 'New' },
  assigned_technician_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  eta_minutes: { type: Number, default: 15 }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);
const ServiceRequest = mongoose.model('ServiceRequest', serviceRequestSchema);

// Middleware for JWT Authentication
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access token required' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
}

// --- API ROUTES ---

// Register User or Technician
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, phone, password, role } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ error: 'Email already registered' });

    const salt = await bcrypt.genSalt(10);
    const password_hash = await bcrypt.hash(password, salt);

    const newUser = new User({
      name,
      email,
      phone,
      password_hash,
      role: role === 'technician' ? 'technician' : 'user',
      approval_status: role === 'admin' ? 'approved' : 'pending'
    });

    await newUser.save();
    res.status(201).json({ message: 'Registration successful. Waiting for admin approval.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: 'Invalid email or password' });

    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) return res.status(400).json({ error: 'Invalid email or password' });

    if (user.role !== 'admin' && user.approval_status !== 'approved') {
      return res.status(403).json({ error: `Account status is ${user.approval_status}. Please wait for admin approval.` });
    }

    const token = jwt.sign({ id: user._id, role: user.role, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, role: user.role, name: user.name });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get Service Requests
app.get('/api/requests', authenticateToken, async (req, res) => {
  try {
    let query = {};
    if (req.user.role === 'user') query.user_id = req.user.id;
    if (req.user.role === 'technician') query.assigned_technician_id = req.user.id;

    const requests = await ServiceRequest.find(query).populate('user_id', 'name phone email').populate('assigned_technician_id', 'name phone');
    res.json(requests);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Create Service Request
app.post('/api/requests', authenticateToken, async (req, res) => {
  try {
    const { service_type, device_details, problem_description, customer_latitude, customer_longitude, customer_address } = req.body;
    const ticket_number = 'EL' + Math.floor(100000 + Math.random() * 900000);

    const newRequest = new ServiceRequest({
      ticket_number,
      user_id: req.user.id,
      service_type,
      device_details,
      problem_description,
      customer_latitude,
      customer_longitude,
      customer_address,
      status: 'New'
    });

    await newRequest.save();
    res.status(201).json(newRequest);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin: Get Users & Technicians Pending Approval
app.get('/api/admin/users', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied' });
  try {
    const users = await User.find({}, '-password_hash');
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin: Update User Approval Status
app.patch('/api/admin/users/:id/approve', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied' });
  try {
    const { status } = req.body; // 'approved' or 'rejected'
    const updated = await User.findByIdAndUpdate(req.params.id, { approval_status: status }, { new: true });
    res.json(updated);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin: Assign Technician to Job
app.patch('/api/requests/:id/assign', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied' });
  try {
    const { technician_id } = req.body;
    const updated = await ServiceRequest.findByIdAndUpdate(
      req.params.id,
      { assigned_technician_id: technician_id, status: 'Technician Assigned' },
      { new: true }
    );
    io.emit('job-assigned', updated);
    res.json(updated);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Portal Route Handlers
app.get('/user', (req, res) => res.sendFile(path.join(__dirname, 'public', 'user.html')));
app.get('/technician', (req, res) => res.sendFile(path.join(__dirname, 'public', 'technician.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));

// Socket.io Real-Time Tracking
io.on('connection', (socket) => {
  console.log('Client connected:', socket.id);

  socket.on('technician-location-update', (data) => {
    // data: { jobId, latitude, longitude, technicianId }
    io.emit(`live-tracking-${data.jobId}`, data);
    io.emit('admin-live-map-update', data);
  });

  socket.on('update-status', async (data) => {
    // data: { jobId, status }
    try {
      await ServiceRequest.findByIdAndUpdate(data.jobId, { status: data.status });
      io.emit(`status-update-${data.jobId}`, data);
    } catch (e) {
      console.error(e);
    }
  });

  socket.on('disconnect', () => {
    console.log('Client disconnected:', socket.id);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`ELOANCE production server running on port ${PORT}`);
}).on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`Port ${PORT} is already in use. Retrying...`);
    setTimeout(() => {
      server.close();
      server.listen(PORT);
    }, 1000);
  } else {
    console.error(err);
  }
});
