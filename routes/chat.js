const express = require('express');
const router = express.Router();
const Message = require('../models/Message');
const authenticateToken = require('../middleware/authMiddleware');

// Get messages for a chat
router.get('/:chatId', authenticateToken, async (req, res) => {
  try {
    const messages = await Message.find({ chatId: req.params.chatId })
      .populate('sender', 'name profilePhoto')
      .sort({ timestamp: 1 });
    res.json(messages);
  } catch (err) {
    res.status(500).json({ msg: err.message });
  }
});

// Send message (will be handled via Socket.io primarily, but this for history)
router.post('/', authenticateToken, async (req, res) => {
  try {
    const message = new Message({ ...req.body, sender: req.user.userId });
    await message.save();
    const populated = await Message.populate(message, { path: 'sender', select: 'name profilePhoto' });
    res.json(populated);
  } catch (err) {
    res.status(500).json({ msg: err.message });
  }
});

module.exports = router;