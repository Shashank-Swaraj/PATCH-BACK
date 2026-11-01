const mongoose = require('mongoose');

async function connectDB() {
  const uri = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/patchback';
  try {
    await mongoose.connect(uri, {
      serverSelectionTimeoutMS: 3000,
    });
    console.log('PATCHBACK MongoDB connected successfully!');
  } catch (error) {
    console.warn('MongoDB connection failed or skipped:', error.message);
    console.warn('Running with in-memory fallback for demo mode.');
  }
}

module.exports = connectDB;
