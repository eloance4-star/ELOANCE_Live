const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const JWT_SECRET = process.env.JWT_SECRET || 'eloance_super_secure_secret_2026';

// Toggle this to TRUE when performing system updates to show the Maintenance page
const IS_MAINTENANCE = false; 

app.use((req, res, next) => {
  if (IS_MAINTENANCE && !req.path.startsWith('/api/admin')) {
    return res.sendFile(path.join(__dirname, 'public', 'maintenance.html'));
  }
  next();
});

let users = [
  { id: 'u_admin', name: 'System Admin', email: 'admin@eloance.com', role: 'admin', approval_status: 'Approved', password_hash: bcrypt.hashSync('admin123', 10) }
];
let technicians = [
  { id: 't1', name: 'Pawan S.', email: 'pawan@eloance.com', phone: '+91 98765 43210', skills: 'Laptop Repair, SSD/RAM Upgrade', vehicle: 'Bike #04', approval_status: 'Approved', online_status: true, latitude: 28.6139, longitude: 77.2090, rating: 4.8 }
];
let serviceRequests = [
  { id: 'EL12345', ticket_number: 'EL12345', customer_name: 'Rahul Sharma', service_type: '20-Min Doorstep Repair', problem_description: 'Laptop not turning on / motherboard issue', customer_address: 'Connaught Place, New Delhi', customer_latitude: 28.6129, customer_longitude: 77.2295, status: 'On The Way', assigned_technician_id: 't1', eta: '12 Minutes', distance: '3.2 KM', rating: null }
];

function verifyToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ success: false, message: 'Access denied. No token provided.' });
  try {
    const verified = jwt.verify(token, JWT_SECRET);
    req.user = verified;
    next();
  } catch (err) {
    res.status(403).json({ success: false, message: 'Invalid token.' });
  }
}

app.post('/api/auth/register', async (req, res) => {
  const { name, email, phone, password, role } = req.body;
  if (!email || !password || !name) return res.status(400).json({ success: false, message: 'Missing required fields.' });
  
  const existing = users.find(u => u.email === email);
  if (existing) return res.status(400).json({ success: false, message: 'Email already registered.' });

  const password_hash = await bcrypt.hash(password, 10);
  const newUser = {
    id: 'u_' + Date.now(),
    name,
    email,
    phone,
    role: role || 'user',
    approval_status: 'Pending',
    password_hash,
    created_at: new Date()
  };
  users.push(newUser);
  res.json({ success: true, message: 'Registration submitted. Waiting for admin approval.', userId: newUser.id });
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email);
  if (!user) return res.status(400).json({ success: false, message: 'Invalid email or password.' });

  const validPass = await bcrypt.compare(password, user.password_hash);
  if (!validPass) return res.status(400).json({ success: false, message: 'Invalid email or password.' });

  if (user.approval_status !== 'Approved' && user.role !== 'admin') {
    return res.status(403).json({ success: false, message: 'Your account is waiting for admin approval.' });
  }

  const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '24h' });
  res.json({ success: true, token, role: user.role, name: user.name });
});

app.get('/api/admin/data', verifyToken, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ success: false, message: 'Unauthorized access.' });
  res.json({ success: true, users, technicians, serviceRequests });
});

app.post('/api/requests/create', verifyToken, (req, res) => {
  const { service_type, problem_description, customer_address } = req.body;
  const newReq = {
    id: 'EL' + Math.floor(10000 + Math.random() * 90000),
    customer_name: req.user.email,
    service_type,
    problem_description,
    customer_address,
    customer_latitude: 28.6129,
    customer_longitude: 77.2295,
    status: 'New',
    assigned_technician_id: null,
    created_at: new Date()
  };
  serviceRequests.push(newReq);
  io.emit('new_service_request', newReq);
  res.json({ success: true, request: newReq });
});

app.post('/api/requests/rate', verifyToken, (req, res) => {
  const { requestId, rating } = req.body;
  const reqItem = serviceRequests.find(r => r.id === requestId);
  if (reqItem) reqItem.rating = rating;
  res.json({ success: true, message: 'Rating saved successfully.' });
});

io.on('connection', (socket) => {
  socket.on('update_technician_location', (data) => {
    const tech = technicians.find(t => t.id === data.technician_id);
    if (tech) {
      tech.latitude = data.latitude;
      tech.longitude = data.longitude;
      tech.online_status = true;
    }
    const job = serviceRequests.find(r => r.id === data.job_id);
    if (job && job.status !== 'Completed' && job.status !== 'Closed') {
      io.emit('live_location_update', data);
    }
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`ELOANCE Production Server running on port ${PORT}`);
});
