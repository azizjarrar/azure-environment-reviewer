const mongoose = require('mongoose');

const reviewSchema = new mongoose.Schema({
  reviewId:       { type: String, required: true, unique: true },
  name:           { type: String, required: true, trim: true },
  userId:         { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  subscriptionId: { type: String, required: true, index: true },
  scanDir:        { type: String, required: true },
  status:         { type: String, enum: ['running', 'complete', 'error'], default: 'running' },
  summary:        { type: mongoose.Schema.Types.Mixed },
  findings:       [{ type: mongoose.Schema.Types.Mixed }],
  sectionsRun:    [String],
  errors:         { type: mongoose.Schema.Types.Mixed },
  reportContent:     { type: String },
  reportGeneratedAt: { type: Date },
  reportPath:        { type: String },
}, { timestamps: true });

module.exports = mongoose.model('Review', reviewSchema);
