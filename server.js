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
         origin: ['http://localhost:5173', 'https://freda-frontend-bau6.onrender.com'], // Replace with your actual Render frontend URL
         methods: ['GET', 'POST', 'PUT', 'DELETE'],
         credentials: true
       },
     });

     app.use(cors({
       origin: ['http://localhost:5173', 'https://freda-frontend-bau6.onrender.com'], // Replace with your actual Render frontend URL
       credentials: true
     }));
     app.use(express.json({ limit: '10mb' }));
     app.use('/uploads', express.static('uploads'));

// MongoDB connection
mongoose
  .connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB'))
  .catch((err) => console.error('MongoDB connection error:', err));

// Schemas
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  name: String,
  profilePhoto: String,
  bio: { type: String, default: '' },
});
const User = mongoose.model('User', userSchema);

const messageSchema = new mongoose.Schema({
  chatId: String,
  text: String,
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  timestamp: { type: Date, default: Date.now },
  type: { type: String, default: 'text' },
});
const Message = mongoose.model('Message', messageSchema);

// Multer setup
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
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
});

// Middleware to verify JWT
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

// Signup
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

// Login
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

// Profile update
app.put('/api/auth/profile', verifyToken, upload.single('photo'), async (req, res) => {
  try {
    const { name, bio } = req.body;
    const updates = {};
    if (name) {
      if (name.length > 50) {
        return res.status(400).json({ message: 'Name must be 50 characters or less' });
      }
      updates.name = name.trim();
    }
    if (bio) {
      if (bio.length > 200) {
        return res.status(400).json({ message: 'Bio must be 200 characters or less' });
      }
      updates.bio = bio.trim();
    }
    if (req.file) {
      const user = await User.findById(req.user.id);
      if (user.profilePhoto) {
        const oldPhotoPath = path.join(__dirname, user.profilePhoto);
        if (fs.existsSync(oldPhotoPath)) {
          fs.unlinkSync(oldPhotoPath);
        }
      }
      updates.profilePhoto = `/uploads/${req.file.filename}`;
    }

    const updatedUser = await User.findByIdAndUpdate(req.user.id, updates, { new: true });
    if (!updatedUser) {
      return res.status(404).json({ message: 'User not found' });
    }

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
    if (err.message.includes('Only JPEG and PNG images are allowed')) {
      return res.status(400).json({ message: err.message });
    }
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ message: 'File size exceeds 5MB limit' });
    }
    res.status(500).json({ message: 'Profile update failed', error: err.message });
  }
});

// Get user profile
app.get('/api/user/:userId', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.params.userId).select('name email profilePhoto bio');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json({
      id: user._id,
      name: user.name,
      email: user.email,
      profilePhoto: user.profilePhoto || null,
      bio: user.bio,
    });
  } catch (err) {
    console.error('Fetch user profile error:', err);
    res.status(500).json({ message: 'Failed to fetch user profile' });
  }
});

// Chat fetch
app.get('/api/chat/:chatId', async (req, res) => {
  try {
    const messages = await Message.find({ chatId: req.params.chatId }).populate('sender', 'name profilePhoto');
    res.json(messages);
  } catch (err) {
    console.error('Chat fetch error:', err);
    res.status(500).json({ message: 'Failed to fetch messages' });
  }
});

// Delete message
app.delete('/api/chat/message/:messageId', verifyToken, async (req, res) => {
  try {
    const message = await Message.findById(req.params.messageId);
    if (!message) {
      return res.status(404).json({ message: 'Message not found' });
    }
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

// Socket.io
io.on('connection', (socket) => {
  console.log('Socket connected:', socket.id);

  socket.on('joinChat', (chatId) => {
    socket.join(chatId);
    console.log(`User joined chat: ${chatId}`);
  });

  socket.on('sendMessage', async ({ chatId, text, sender, type }) => {
    try {
      const message = new Message({ chatId, text, sender, type });
      await message.save();
      const populatedMessage = await Message.findById(message._id).populate('sender', 'name profilePhoto');
      io.to(chatId).emit('newMessage', populatedMessage);
    } catch (err) {
      console.error('Send message error:', err);
    }
  });

  socket.on('deleteMessage', async ({ chatId, messageId }) => {
    try {
      io.to(chatId).emit('messageDeleted', { messageId });
    } catch (err) {
      console.error('Delete message broadcast error:', err);
    }
  });
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, '0.0.0.0', () => console.log(`Server running on http://0.0.0.0:${PORT}`));