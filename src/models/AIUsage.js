'use strict';
const mongoose = require('mongoose');

const aiUsageSchema = new mongoose.Schema({
  userId:       { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  type:         { type: String, enum: ['report', 'chat'], required: true },
  reviewId:     { type: String },
  inputTokens:  { type: Number, default: 0 },
  outputTokens: { type: Number, default: 0 },
  costUSD:      { type: Number, default: 0 },
  model:        { type: String, default: 'gpt-4.1' },
}, { timestamps: true });

module.exports = mongoose.model('AIUsage', aiUsageSchema);
