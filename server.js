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

// Database Connection & Secrets
const mongoose = require('mongoose');
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/eloance';

mongoose.connect(MONGO_URI)
  .then(() => console.log('Connected to MongoDB Atlas successfully'))
  .catch(err => {
    console.error('MongoDB connection error:', err.messege);
    process.exit(1); // Exits cleanly so Render can log the error and retry
  });

// --- MONGODB SCHEMAS ---
const productSchema = new mongoose.Schema({
  title: { type: String, required: true },
  category: { type: String, required: true },
  price: { type: Number, required: true },
  original_price: { type: Number },
  image_url: { type: String, required: true },
  description: { type: String },
  badge: { type: String }
}, { timestamps: true });

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  phone: { type: String },
  password_hash: { type: String, required: true },
  role: { type: String, enum: ['user', 'technician', 'admin'], default: 'user' },
  approval_status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  skills: [String],
  experience: String,
  service_area: String,
  vehicle_number: String,
  cv_filename: String
}, { timestamps: true });

const serviceRequestSchema = new mongoose.Schema({
  ticket_number: { type: String, required: true, unique: true },
  user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  service_type: { type: String, required: true },
  category_detail: { type: String, required: true },
  device_details: { type: String, required: true },
  problem_description: { type: String, required: true },
  customer_address: String,
  status: { type: String, default: 'New' },
  assigned_technician_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  payment_status: { type: String, enum: ['Pending', 'Paid'], default: 'Pending' },
  payment_amount: { type: Number, default: 49 },
  eta_minutes: { type: Number, default: 20 }
}, { timestamps: true });

const Product = mongoose.model('Product', productSchema);
const User = mongoose.model('User', userSchema);
const ServiceRequest = mongoose.model('ServiceRequest', serviceRequestSchema);

// Seed initial products if collection is empty
Product.countDocuments().then(count => {
  if (count === 0) {
    Product.insertMany([
      { title: "MacBook Pro M1 (Refurbished A+)", category: "Refurbished", price: 699, original_price: 999, image_url: "https://images.unsplash.com/photo-1517336714731-489689fd1ca8?w=500", description: "16GB RAM, 512GB SSD, flawless retina display.", badge: "Best Seller" },
      { title: "High-Speed 1TB NVMe SSD Upgrade", category: "Festival Offer", price: 89, original_price: 149, image_url: "https://images.unsplash.com/photo-1597872200969-2b65d56bd16b?w=500", description: "Boost speed up to 7000MB/s with 20-min robot install.", badge: "30% OFF" },
      { title: "Original Replacement Battery", category: "Accessory", price: 59, original_price: 99, image_url: "https://images.unsplash.com/photo-1618788372246-79faff0c3742?w=500", description: "OEM battery replacement for Dell, HP, Lenovo & MacBooks.", badge: "1 Yr Warranty" }
    ]);
  }
});

// JWT Middleware
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

// --- PRODUCT API ENDPOINTS ---
app.get('/api/products', async (req, res) => {
  try {
    const products = await Product.find({});
    res.json(products);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/admin/products', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied' });
  try {
    const newProduct = new Product(req.body);
    await newProduct.save();
    res.status(201).json(newProduct);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/admin/products/:id', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied' });
  try {
    await Product.findByIdAndDelete(req.params.id);
    res.json({ message: 'Product deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- AUTH API ROUTES ---
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, phone, password, role, skills, experience, service_area, vehicle_number, cv_filename } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ error: 'Email already registered' });

    const salt = await bcrypt.genSalt(10);
    const password_hash = await bcrypt.hash(password, salt);

    const newUser = new User({
      name,
      email,
      phone,
      password_hash,
      role: role === 'technician' ? 'technician' : (role === 'admin' ? 'admin' : 'user'),
      approval_status: role === 'admin' ? 'approved' : 'pending',
      skills: skills || [],
      experience,
      service_area,
      vehicle_number,
      cv_filename
    });

    await newUser.save();
    res.status(201).json({ message: 'Registration submitted successfully. Pending admin approval.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: 'Invalid email or password' });

    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) return res.status(400).json({ error: 'Invalid email or password' });

    if (user.role !== 'admin' && user.approval_status !== 'approved') {
      return res.status(403).json({ error: `Account status is ${user.approval_status}. Awaiting admin approval.` });
    }

    const token = jwt.sign({ id: user._id, role: user.role, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, role: user.role, name: user.name });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- SERVICE REQUEST API ---
app.post('/api/requests', authenticateToken, async (req, res) => {
  try {
    const { service_type, category_detail, device_details, problem_description, customer_address } = req.body;
    const ticket_number = 'EL-' + Math.floor(100000 + Math.random() * 900000);

    const newRequest = new ServiceRequest({
      ticket_number,
      user_id: req.user.id,
      service_type,
      category_detail,
      device_details,
      problem_description,
      customer_address,
      status: 'New'
    });

    await newRequest.save();
    res.status(201).json({ message: 'Service request created', ticket_number });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- ADMIN MANAGEMENT API ---
app.get('/api/admin/users', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied' });
  try {
    const users = await User.find({}, '-password_hash');
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/admin/users/:id/approve', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied' });
  try {
    const { status } = req.body;
    const updated = await User.findByIdAndUpdate(req.params.id, { approval_status: status }, { new: true });
    res.json(updated);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- PORTAL ROUTE HANDLERS ---
app.get('/user', (req, res) => res.sendFile(path.join(__dirname, 'public', 'user.html')));
app.get('/technician', (req, res) => res.sendFile(path.join(__dirname, 'public', 'technician.html')));
app.get('/admin-secret-access', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));

// --- SOCKET.IO REAL-TIME TRACKING ---
io.on('connection', (socket) => {
  socket.on('technician-location-update', (data) => {
    io.emit(`live-tracking-${data.jobId}`, data);
  });
});

// Safe Port Listener with EADDRINUSE conflict recovery
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
