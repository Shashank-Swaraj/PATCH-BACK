
const mongoose = require('mongoose');

const analysisSchema = new mongoose.Schema({
  userId: {
    type: String,
    required: true
  },

  scenarioName: {
    type: String,
    default: 'Custom Analysis'
  },

  sink: {
    type: String,
    default: ''
  },

  guard: {
    type: String,
    default: ''
  },

  verdict: {
    type: String,
    enum: ['PROVEN_REGRESSION', 'SAFE_PASS'],
    required: true
  },

  violations: {
    type: Array,
    default: []
  },

  latencyMs: {
    type: Number,
    default: 0
  },

  createdAt: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model('Analysis', analysisSchema);
