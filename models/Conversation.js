const mongoose = require('mongoose');

const conversationSchema = new mongoose.Schema({
  conversationId: { type: String, required: true, unique: true },
  participants: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  lastMessage: { type: String, default: '' },
  lastMessageTime: { type: Date, default: Date.now },
}, { timestamps: true });

conversationSchema.index({ participants: 1, lastMessageTime: -1 });

module.exports = mongoose.model('Conversation', conversationSchema);
