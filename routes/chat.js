const express = require('express');
const router = express.Router();
const Message = require('../models/Message');
const Conversation = require('../models/Conversation');
const User = require('../models/User');
const authenticateToken = require('./auth');  // Reuse from auth.js

// Get messages for a chat (group or direct)
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

// Get or create a direct message conversation
router.post('/direct/start', authenticateToken, async (req, res) => {
  try {
    const { recipientId } = req.body;
    const userId = req.user.id;

    if (!recipientId) {
      return res.status(400).json({ msg: 'Recipient ID is required' });
    }

    // Verify recipient exists
    const recipient = await User.findById(recipientId);
    if (!recipient) {
      return res.status(404).json({ msg: 'Recipient not found' });
    }

    // Create a consistent conversation ID (sort IDs to ensure same ID regardless of order)
    const ids = [userId, recipientId].sort();
    const conversationId = `direct-${ids[0]}-${ids[1]}`;

    // Find or create conversation
    let conversation = await Conversation.findOne({ conversationId })
      .populate('participants', 'name profilePhoto');

    if (!conversation) {
      conversation = new Conversation({
        conversationId,
        participants: [userId, recipientId],
      });
      await conversation.save();
      await conversation.populate('participants', 'name profilePhoto');
    }

    res.json(conversation);
  } catch (err) {
    res.status(500).json({ msg: err.message });
  }
});

// Get all direct message conversations for a user
router.get('/user/conversations', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const conversations = await Conversation.find({ participants: userId })
      .populate('participants', 'name profilePhoto email')
      .populate('lastMessage')
      .sort({ lastMessageTime: -1 });

    // Transform to include other participant info
    const transformedConversations = conversations.map((conv) => {
      const otherParticipant = conv.participants.find(
        (p) => p._id.toString() !== userId
      );
      return {
        ...conv.toObject(),
        otherParticipant,
      };
    });

    res.json(transformedConversations);
  } catch (err) {
    res.status(500).json({ msg: err.message });
  }
});

// Delete a message
router.delete('/message/:messageId', authenticateToken, async (req, res) => {
  try {
    const message = await Message.findById(req.params.messageId);
    if (!message) {
      return res.status(404).json({ msg: 'Message not found' });
    }

    // Verify ownership
    if (message.sender.toString() !== req.user.id) {
      return res.status(403).json({ msg: 'Not authorized to delete this message' });
    }

    await Message.findByIdAndDelete(req.params.messageId);
    res.json({ msg: 'Message deleted' });
  } catch (err) {
    res.status(500).json({ msg: err.message });
  }
});

module.exports = router;