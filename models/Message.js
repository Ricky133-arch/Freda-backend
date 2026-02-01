const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({
  chatId: { type: String, required: true },  // Unique ID for chat room or 'direct-userId1-userId2'
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  text: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
  type: { type: String, enum: ['group', 'direct'], default: 'group' },  // Message type
});

module.exports = mongoose.model('Message', messageSchema);