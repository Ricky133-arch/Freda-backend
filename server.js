const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const http = require('http');
const { Server } = require('socket.io');
require('dotenv').config();

const app = express();
const server = http.createServer(app);

// === SOCKET.IO SETUP ===
const io = new Server(server, {
  cors: {
    origin: ['https://freda-frontend.onrender.com', 'http://localhost:5173'], // add localhost for dev
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true
  },
});

app.use(cors({
  origin: ['https://freda-frontend.onrender.com', 'http://localhost:5173'],
  credentials: true
}));
app.use(express.json({ limit: '50mb' })); // increased for media
app.use('/uploads', express.static('uploads'));

// Ensure uploads folder exists
if (!fs.existsSync('./uploads')) {
  fs.mkdirSync('./uploads');
}

// MongoDB connection
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log('MongoDB Connected'))
  .catch(err => console.error('MongoDB error:', err));

// === SCHEMAS ===
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  name: { type: String, required: true },
  profilePhoto: String,
  bio: { type: String, default: '' },
  onlineStatus: { type: Boolean, default: false },
  lastSeen: { type: Date, default: Date.now },
  fcmToken: String, // for push notifications
});
const User = mongoose.model('User', userSchema);

const chatSchema = new mongoose.Schema({
  participants: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  chatId: { type: String, unique: true, required: true }, // e.g., "abc123_def456"
  lastMessage: { type: mongoose.Schema.Types.ObjectId, ref: 'Message' },
  createdAt: { type: Date, default: Date.now }
});
const Chat = mongoose.model('Chat', chatSchema);

const messageSchema = new mongoose.Schema({
  chatId: { type: String, required: true },
  text: String,
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  timestamp: { type: Date, default: Date.now },
  type: { type: String, default: 'text' }, // text, image, video, audio
  mediaUrl: String,
  mediaType: String,
  reactions: [{
    emoji: String,
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
  }]
});
const Message = mongoose.model('Message', messageSchema);

// === MULTER - Profile + Media Uploads ===
const storage = multer.diskStorage({
  destination: './uploads/',
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname));
  }
});

const fileFilter = (req, file, cb) => {
  const allowed = [
    'image/jpeg', 'image/png', 'image/gif',
    'video/mp4', 'video/webm', 'video/quicktime',
    'audio/mpeg', 'audio/wav', 'audio/ogg'
  ];
  if (allowed.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('File type not allowed'), false);
  }
};

const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: 50 * 1024 * 1024 } // 50MB
});

// === JWT MIDDLEWARE ===
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token provided' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ message: 'Invalid token' });
  }
};

// === AUTH ROUTES (unchanged except small fixes) ===
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, password, name, bio } = req.body;
    if (!email || !password || !name) return res.status(400).json({ message: 'Missing fields' });

    const exists = await User.findOne({ email });
    if (exists) return res.status(400).json({ message: 'Email already exists' });

    const hashed = await bcrypt.hash(password, 10);
    const user = new User({ email, password: hashed, name, bio: bio || '' });
    await user.save();

    const token = jwt.sign({ id: user._id, email, name }, process.env.JWT_SECRET, { expiresIn: '7d' });

    res.status(201).json({
      token,
      user: { id: user._id, email, name, profilePhoto: null, bio: user.bio }
    });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user._id, email, name: user.name }, process.env.JWT_SECRET, { expiresIn: '7d' });

    res.json({
      token,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        profilePhoto: user.profilePhoto,
        bio: user.bio
      }
    });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/api/auth/profile', verifyToken, upload.single('photo'), async (req, res) => {
  // ... (your original code - unchanged, just kept for completeness)
  // ... [same as before]
});

// === NEW ROUTES ===

// Get user profile
app.get('/api/user/:id', verifyToken, async (req, res) => {
  const user = await User.findById(req.params.id).select('name email profilePhoto bio onlineStatus');
  if (!user) return res.status(404).json({ message: 'User not found' });
  res.json(user);
});

// Search users
app.get('/api/users/search', verifyToken, async (req, res) => {
  const { q } = req.query;
  if (!q) return res.json([]);
  const users = await User.find({
    $or: [
      { name: { $regex: q, $options: 'i' } },
      { email: { $regex: q, $options: 'i' } }
    ],
    _id: { $ne: req.user.id }
  }).select('name email profilePhoto').limit(10);
  res.json(users);
});

// Create or get private chat
app.post('/api/chat/create', verifyToken, async (req, res) => {
  const { userId: participantId } = req.body;
  const ids = [req.user.id, participantId].sort();
  const chatId = ids.join('_');

  let chat = await Chat.findOne({ chatId });
  if (!chat) {
    chat = new Chat({ participants: ids, chatId });
    await chat.save();
  }
  res.json({ chatId });
});

// Get user's chat list
app.get('/api/chats', verifyToken, async (req, res) => {
  const chats = await Chat.find({ participants: req.user.id })
    .populate('participants', 'name profilePhoto onlineStatus')
    .populate('lastMessage')
    .sort({ createdAt: -1 });
  res.json(chats);
});

// Get messages in a chat
app.get('/api/chat/:chatId/messages', verifyToken, async (req, res) => {
  const { chatId } = req.params;
  const chat = await Chat.findOne({ chatId, participants: req.user.id });
  if (!chat) return res.status(403).json({ message: 'Access denied' });

  const messages = await Message.find({ chatId })
    .populate('sender', 'name profilePhoto')
    .populate('reactions.user', 'name')
    .sort({ timestamp: 1 })
    .sort({ timestamp: 1 });

  res.json(messages);
});

// Upload media (images, videos, audio)
app.post('/api/media/upload', verifyToken, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ message: 'No file' });
  res.json({
    url: `/uploads/${req.file.filename}`,
    type: req.file.mimetype
  });
});

// React to message
app.post('/api/message/:id/react', verifyToken, async (req, res) => {
  const { emoji } = req.body;
  const message = await Message.findById(req.params.id);
  if (!message) return res.status(404).json({ message: 'Not found' });

  const existing = message.reactions.find(r => 
    r.user.toString() === req.user.id && r.emoji === emoji
  );

  if (existing) {
    message.reactions.pull(existing._id);
  } else {
    message.reactions.push({ emoji, user: req.user.id });
  }
  await message.save();

  const populated = await Message.findById(message._id)
    .populate('sender', 'name profilePhoto')
    .populate('reactions.user', 'name');

  io.to(message.chatId).emit('messageUpdated', populated);
  res.json(populated);
});

// Delete message (your original route - kept)
app.delete('/api/chat/message/:messageId', verifyToken, async (req, res) => {
  // ... same as before
});

// === SOCKET.IO - REAL-TIME FEATURES ===
const onlineUsers = new Map(); // socket.id → userId

io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  // User comes online
  socket.on('setOnline', async (userId) => {
    socket.userId = userId;
    onlineUsers.set(socket.id, userId);
    await User.findByIdAndUpdate(userId, { onlineStatus: true });

    io.emit('userOnline', { userId, online: true });
  });

  socket.on('joinChat', (chatId) => {
    socket.join(chatId);
  });

  // Typing indicator
  socket.on('typing', ({ chatId, isTyping }) => {
    socket.to(chatId).emit('userTyping', { userId: socket.userId, isTyping });
  });

  // Send message (text or media)
  socket.on('sendMessage', async (data) => {
    const message = new Message({
      chatId: data.chatId,
      text: data.text || '',
      sender: socket.userId,
      type: data.type || 'text',
      mediaUrl: data.mediaUrl,
      mediaType: data.mediaType
    });
    await message.save();

    // Update chat's last message
    await Chat.findOneAndUpdate({ chatId: data.chatId }, { lastMessage: message._id });

    const populated = await Message.findById(message._id)
      .populate('sender', 'name profilePhoto onlineStatus')
      .populate('reactions.user', 'name');

    io.to(data.chatId).emit('newMessage', populated);
  });

  // WebRTC Call Signaling
  socket.on('callUser', (data) => {
    io.to(data.userToCall).emit('incomingCall', {
      signal: data.signal,
      from: socket.userId,
      chatId: data.chatId
    });
  });

  socket.on('answerCall', (data) => {
    io.to(data.to).emit('callAccepted', data.signal);
  });

  socket.on('rejectCall', (data) => {
    io.to(data.to).emit('callRejected');
  });

  socket.on('disconnect', async () => {
    const userId = onlineUsers.get(socket.id);
    if (userId) {
      onlineUsers.delete(socket.id);
      await User.findByIdAndUpdate(userId, { onlineStatus: false, lastSeen: new Date() });
      io.emit('userOnline', { userId, online: false });
    }
  });
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`Freda Server running on port ${PORT}`);
  console.log(`Visit: https://freda-frontend.onrender.com`);
});