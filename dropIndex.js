require('dotenv').config(); // Load .env file
const mongoose = require('mongoose');

async function dropUsernameIndex() {
  try {
    const uri = process.env.MONGO_URI;
    if (!uri) {
      throw new Error('MONGO_URI is not defined in .env file');
    }
    await mongoose.connect(uri, {
      useNewUrlParser: true,
      useUnifiedTopology: true
    });
    console.log('Connected to MongoDB');
    await mongoose.connection.db.collection('users').dropIndex('username_1');
    console.log('Dropped username_1 index');
    await mongoose.connection.close();
    console.log('MongoDB connection closed');
  } catch (err) {
    console.error('Error:', err.message);
    process.exit(1);
  }
}

dropUsernameIndex();