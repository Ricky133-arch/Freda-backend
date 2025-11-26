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
const io = new Server(server, {
  cors: {
    origin: ['https://freda-frontend.onrender.com'],
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true
  },
});

app.use(cors({
  origin: ['https://freda-frontend.onrender.com'],
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use('/uploads', express.static('uploads'));

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// === SCHEMAS ===
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  name: String,
  profilePhoto: String,
  bio: { type: String, default: '' },
});
const User = mongoose.model('User', userSchema);

const messageSchema = new mongoose.Schema({
  chatId: { type: String, required: true },
  text: String,
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  timestamp: { type: Date, default: Date.now },
  type: { type: String, default: 'text' }, // text, image, etc.
});
const Message = mongoose.model('Message', messageSchema);

// Chat Model (supports both DM & Group)
const chatSchema = new mongoose.Schema({
  chatId: { type: String, required: true, unique: true },
  participants: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  type: { type: String, enum: ['dm', 'group'], default: 'dm' },
  groupName: { type: String }, // only for group chats
  createdAt: { type: Date, default: Date.now },
});
const Chat = mongoose.model('Chat', chatSchema);

// Multer for profile photos
const storage = multer.diskStorage({
  destination: './uploads/',
  filename: (req, file, cb) => cb(null, `${Date.now()}-${file.originalname}`),
});
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ['image/jpeg', 'image/jpg', 'image/png'];
    allowed.includes(file.mimetype) ? cb(null, true) : cb(new Error('Invalid file type'));
  }
});

// JWT Middleware
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Unauthorized' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (err) {
    res.status(401).json({ message: 'Invalid token' });
  }
};

// === AUTH ROUTES ===
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, password, name, bio } = req.body;
    if (!email || !password || !name) return res.status(400).json({ message: 'Required fields missing' });
    if (await User.findOne({ email })) return res.status(400).json({ message: 'Email already exists' });

    const user = new User({ email, password: await bcrypt.hash(password, 10), name, bio: bio || '' });
    await user.save();

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ token, user: { id: user._id, email, name, profilePhoto: null, bio: user.bio } });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || !await bcrypt.compare(password, user.password))
      return res.status(401).json({ message: 'Invalid credentials' });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user._id, email, name: user.name, profilePhoto: user.profilePhoto, bio: user.bio } });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/api/auth/profile', verifyToken, upload.single('photo'), async (req, res) => {
  try {
    const updates = {};
    if (req.body.name) updates.name = req.body.name.trim();
    if (req.body.bio) updates.bio = req.body.bio.trim();
    if (req.file) {
      const user = await User.findById(req.user.id);
      if (user.profilePhoto) fs.unlinkSync(path.join(__dirname, user.profilePhoto));
      updates.profilePhoto = `/uploads/${req.file.filename}`;
    }
    const updated = await User.findByIdAndUpdate(req.user.id, updates, { new: true });
    res.json({ user: { id: updated._id, email: updated.email, name: updated.name, profilePhoto: updated.profilePhoto, bio: updated.bio } });
  } catch (err) {
    res.status(500).json({ message: 'Update failed' });
  }
});

app.get('/api/user/:userId', verifyToken, async (req, res) => {
  const user = await User.findById(req.params.userId).select('name email profilePhoto bio');
  if (!user) return res.status(404).json({ message: 'User not found' });
  res.json({ id: user._id, name: user.name, email: user.email, profilePhoto: user.profilePhoto, bio: user.bio });
});

// === CHAT & DM FEATURES ===

// 1. Start DM with someone
app.post('/api/dm/start/:userId', verifyToken, async (req, res) => {
  const userA = req.user.id;
  const userB = req.params.userId;
  if (userA === userB) return res.status(400).json({ message: "Can't DM yourself" });

  const sorted = [userA, userB].sort();
  const chatId = `dm_${sorted[0]}_${sorted[1]}`;

  let chat = await Chat.findOne({ chatId });
  if (!chat) {
    chat = new Chat({ chatId, participants: sorted, type: 'dm' });
    await chat.save();
  }

  res.json({ chatId });
});

// 2. Create Group Chat
app.post('/api/group/create', verifyToken, async (req, res) => {
  const { name, memberIds } = req.body;
  if (!memberIds || memberIds.length < 2) return res.status(400).json({ message: 'Need at least 2 members' });

  const participants = [...new Set([req.user.id, ...memberIds])];
  const chatId = `group_${Date.now()}_${Math.random().toString(36).substr(2, 5)}`;

  const chat = new Chat({ chatId, participants, type: 'group', groupName: name });
  await chat.save();

  res.json({ chatId, groupName: name, participants });
});

// 3. Get all chats (DMs + Groups)
app.get('/api/chats', verifyToken, async (req, res) => {
  const chats = await Chat.find({ participants: req.user.id })
    .populate('participants', 'name profilePhoto');

  const result = await Promise.all(chats.map(async chat => {
    const lastMsg = await Message.findOne({ chatId: chat.chatId }).sort({ timestamp: -1 });

    if (chat.type === 'dm') {
      const other = chat.participants.find(p => p._id.toString() !== req.user.id);
      return {
        chatId: chat.chatId,
        type: 'dm',
        otherUser: { id: other._id, name: other.name, profilePhoto: other.profilePhoto },
        lastMessage: lastMsg ? (lastMsg.type === 'text' ? lastMsg.text : 'Photo') : 'No messages',
        lastTimestamp: lastMsg?.timestamp || chat.createdAt
      };
    } else {
      return {
        chatId: chat.chatId,
        type: 'group',
        groupName: chat.groupName,
        participants: chat.participants.map(p => ({ id: p._id, name: p.name, profilePhoto: p.profilePhoto })),
        lastMessage: lastMsg ? (lastMsg.type === 'text' ? lastMsg.text : 'Photo') : 'No messages',
        lastTimestamp: lastMsg?.timestamp || chat.createdAt
      };
    }
  }));

  result.sort((a, b) => (b.lastTimestamp || 0) - (a.lastTimestamp || 0));
  res.json(result);
});

// 4. Fetch messages (secured)
app.get('/api/chat/:chatId', verifyToken, async (req, res) => {
  const chat = await Chat.findOne({ chatId: req.params.chatId });
  if (chat && !chat.participants.map(p => p.toString()).includes(req.user.id))
    return res.status(403).json({ message: 'Access denied' });

  const messages = await Message.find({ chatId: req.params.chatId })
    .populate('sender', 'name profilePhoto')
    .sort({ timestamp: 1 });

  res.json(messages);
});

// 5. Delete own message
app.delete('/api/chat/message/:messageId', verifyToken, async (req, res) => {
  const message = await Message.findById(req.params.messageId);
  if (!message) return res.status(404).json({ message: 'Not found' });
  if (message.sender.toString() !== req.user.id)
    return res.status(403).json({ message: 'Not allowed' });

  await Message.deleteOne({ _id: req.params.messageId });
  res.json({ success: true });
});

// === SOCKET.IO WITH AUTH ===
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('Auth required'));
  try {
    socket.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (err) {
    next(new Error('Invalid token'));
  }
});

io.on('connection', (socket) => {
  console.log('Connected:', socket.user.id);

  socket.on('joinChat', async (chatId) => {
    const chat = await Chat.findOne({ chatId });
    if (chat && chat.participants.map(p => p.toString()).includes(socket.user.id)) {
      socket.join(chatId);
    }
  });

  socket.on('sendMessage', async ({ chatId, text, type = 'text' }) => {
    const chat = await Chat.findOne({ chatId });
    if (!chat || !chat.participants.map(p => p.toString()).includes(socket.user.id)) return;

    const message = new Message({ chatId, text, sender: socket.user.id, type });
    await message.save();

    const populated = await Message.findById(message._id).populate('sender', 'name profilePhoto');
    io.to(chatId).emit('newMessage', populated);
  });

  socket.on('deleteMessage', async ({ chatId, messageId }) => {
    const message = await Message.findById(messageId);
    if (message && message.sender.toString() === socket.user.id) {
      await Message.deleteOne({ _id: messageId });
      io.to(chatId).emit('messageDeleted', { messageId });
    }
  });
});

// Start Server
const PORT = process.env.PORT || 5000;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});