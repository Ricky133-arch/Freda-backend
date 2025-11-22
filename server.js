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

// Socket.IO setup
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

// MongoDB connection
mongoose
  .connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB'))
  .catch((err) => console.error('MongoDB connection error:', err));

// === EXISTING SCHEMAS (UNCHANGED) ===
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  name: String,
  profilePhoto: String,
  bio: { type: String, default: '' },
});
const User = mongoose.model('User', userSchema);

// Keep your original Message model (for group chat)
const messageSchema = new mongoose.Schema({
  chatId: String, // "group" or custom string for group
  text: String,
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  timestamp: { type: Date, default: Date.now },
  type: { type: String, default: 'text' },
});
const Message = mongoose.model('Message', messageSchema);

// === NEW: DM Conversation Model (ADDED, does NOT affect group chat) ===
const conversationSchema = new mongoose.Schema({
  participants: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  isGroup: { type: Boolean, default: false },
  groupName: { type: String }, // only used if isGroup: true
  lastMessageAt: { type: Date, default: Date.now },
});
const Conversation = mongoose.model('Conversation', conversationSchema);

// Multer setup (unchanged)
const storage = multer.diskStorage({
  destination: './uploads/',
  filename: (req, file, cb) => cb(null, `${Date.now()}${path.extname(file.originalname)}`),
});
const fileFilter = (req, file, cb) => {
  const allowedTypes = ['image/jpeg', 'image/png'];
  if (!allowedTypes.includes(file.mimetype)) {
    return cb(new Error('Only JPEG and PNG images are allowed'), false);
  }
  cb(null, true);
};
const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: 5 * 1024 * 1024 },
});

// JWT Middleware (unchanged)
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Unauthorized' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid token' });
  }
};

// === ALL YOUR ORIGINAL ROUTES (100% UNCHANGED) ===
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, password, name, bio } = req.body;
    if (!email || !password || !name) {
      return res.status(400).json({ message: 'Email, password, and name are required' });
    }
    if (name.length > 50) {
      return res.status(400).json({ message: 'Name must be 50 characters or less' });
    }
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'Email already exists' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ email, password: hashedPassword, name, bio: bio || '' });
    await user.save();
    const token = jwt.sign({ id: user._id, email, name }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.status(201).json({
      token,
      user: { id: user._id, email, name, profilePhoto: null, bio: user.bio },
    });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ message: 'Server error during signup' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ message: 'Invalid email or password' });
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ message: 'Invalid email or password' });

    const token = jwt.sign({ id: user._id, email, name: user.name }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({
      token,
      user: { id: user._id, email, name: user.name, profilePhoto: user.profilePhoto || null, bio: user.bio },
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Server error during login' });
  }
});

app.put('/api/auth/profile', verifyToken, upload.single('photo'), async (req, res) => {
  try {
    const { name, bio } = req.body;
    const updates = {};
    if (name) {
      if (name.length > 50) return res.status(400).json({ message: 'Name must be 50 characters or less' });
      updates.name = name.trim();
    }
    if (bio) {
      if (bio.length > 200) return res.status(400).json({ message: 'Bio must be 200 characters or less' });
      updates.bio = bio.trim();
    }
    if (req.file) {
      const user = await User.findById(req.user.id);
      if (user.profilePhoto) {
        const oldPhotoPath = path.join(__dirname, user.profilePhoto);
        if (fs.existsSync(oldPhotoPath)) fs.unlinkSync(oldPhotoPath);
      }
      updates.profilePhoto = `/uploads/${req.file.filename}`;
    }

    const updatedUser = await User.findByIdAndUpdate(req.user.id, updates, { new: true });
    if (!updatedUser) return res.status(404).json({ message: 'User not found' });

    res.json({
      user: {
        id: updatedUser._id,
        email: updatedUser.email,
        name: updatedUser.name,
        profilePhoto: updatedUser.profilePhoto || null,
        bio: updatedUser.bio,
      },
    });
  } catch (err) {
    console.error('Profile update error:', err);
    res.status(500).json({ message: 'Profile update failed' });
  }
});

app.get('/api/user/:userId', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.params.userId).select('name email profilePhoto bio');
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json({
      id: user._id,
      name: user.name,
      email: user.email,
      profilePhoto: user.profilePhoto || null,
      bio: user.bio,
    });
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch user profile' });
  }
});

// === GROUP CHAT ENDPOINTS (UNCHANGED) ===
app.get('/api/chat/:chatId', async (req, res) => {
  try {
    const messages = await Message.find({ chatId: req.params.chatId }).populate('sender', 'name profilePhoto').sort({ timestamp: 1 });
    res.json(messages);
  } catch (err) {
    console.error('Chat fetch error:', err);
    res.status(500).json({ message: 'Failed to fetch messages' });
  }
});

app.delete('/api/chat/message/:messageId', verifyToken, async (req, res) => {
  try {
    const message = await Message.findById(req.params.messageId);
    if (!message) return res.status(404).json({ message: 'Message not found' });
    if (message.sender.toString() !== req.user.id) {
      return res.status(403).json({ message: 'Unauthorized to delete this message' });
    }
    await Message.deleteOne({ _id: req.params.messageId });
    res.json({ message: 'Message deleted successfully' });
  } catch (err) {
    console.error('Delete message error:', err);
    res.status(500).json({ message: 'Failed to delete message' });
  }
});

// === NEW: DM FEATURES (ADDED SAFELY) ===

// 1. Get all DM conversations for current user
app.get('/api/conversations', verifyToken, async (req, res) => {
  try {
    const conversations = await Conversation.find({
      participants: req.user.id,
      isGroup: false
    })
      .populate('participants', 'name profilePhoto')
      .sort({ lastMessageAt: -1 });

    const result = await Promise.all(conversations.map(async (conv) => {
      const lastMsg = await Message.findOne({
        chatId: conv._id.toString()
      }).sort({ timestamp: -1 });

      const otherUser = conv.participants.find(p => p._id.toString() !== req.user.id);

      return {
        _id: conv._id,
        user: otherUser ? {
          id: otherUser._id,
          name: otherUser.name,
          profilePhoto: otherUser.profilePhoto
        } : null,
        lastMessage: lastMsg ? lastMsg.text : '',
        lastMessageTime: lastMsg ? lastMsg.timestamp : conv.lastMessageAt,
      };
    }));

    res.json(await result);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to load DMs' });
  }
});

// 2. Create or get DM conversation with another user
app.post('/api/conversations/dm', verifyToken, async (req, res) => {
  try {
    const { userId } = req.body;

    let conversation = await Conversation.findOne({
      participants: { $all: [req.user.id, userId] },
      isGroup: false
    });

    if (!conversation) {
      conversation = new Conversation({
        participants: [req.user.id, userId],
        isGroup: false
      });
      await conversation.save();
    }

    await conversation.populate('participants', 'name profilePhoto');
    res.json(conversation);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to start DM' });
  }
});

// === SOCKET.IO (supports both group & DMs) ===
io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  // Join room (works for both group "group-chat-123" and DM conversation IDs)
  socket.on('joinChat', (roomId) => {
    socket.join(roomId);
  });

  // Send message (works for group AND DMs)
  socket.on('sendMessage', async ({ chatId, text, sender, type = 'text' }) => {
    try {
      const message = new Message({ chatId, text, sender, type });
      await message.save();

      const populated = await Message.findById(message._id).populate('sender', 'name profilePhoto');

      // Update last message time for DMs
      if (chatId.length === 24) { // MongoDB ObjectId length check → likely a DM
        await Conversation.findByIdAndUpdate(chatId, { lastMessageAt: new Date() });
      }

      io.to(chatId).emit('newMessage', populated);
    } catch (err) {
      console.error('Send message error:', err);
    }
  });

  socket.on('deleteMessage', ({ chatId, messageId }) => {
    io.to(chatId).emit('messageDeleted', { messageId });
  });

  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.id);
  });
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on http://0.0.0.0:${PORT}`);
});