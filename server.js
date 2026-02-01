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

// MongoDB connection
mongoose
  .connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB'))
  .catch((err) => console.error('MongoDB connection error:', err));

// Use centralized models
const User = require('./models/User');
const Message = require('./models/Message');
let Conversation;
try {
  Conversation = require('./models/Conversation');
} catch (e) {
  // Conversation model may not exist yet during edits — that's fine.
  Conversation = null;
}

// Mount routers if present
try {
  const authRoutes = require('./routes/auth');
  app.use('/api/auth', authRoutes);
} catch (e) {
  // ignore if routes/auth isn't present or has issues
}
try {
  const chatRoutes = require('./routes/chat');
  app.use('/api/chat', chatRoutes);
} catch (e) {
  // ignore if routes/chat isn't present or has issues
}

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

// Note: auth and chat REST endpoints are provided by mounted routers

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
      // If this is a direct conversation, update or create Conversation metadata
      try {
        if (Conversation && typeof chatId === 'string' && chatId.startsWith('direct-')) {
          // Expect conversationId format: direct-<idA>-<idB>
          const convId = chatId;
          const parts = convId.split('-');
          const ids = parts.slice(1);
          const participants = ids;
          await Conversation.findOneAndUpdate(
            { conversationId: convId },
            { $set: { lastMessage: text, lastMessageTime: new Date(), participants } },
            { upsert: true, new: true }
          );
        }
      } catch (e) {
        console.error('Conversation update error:', e);
      }
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