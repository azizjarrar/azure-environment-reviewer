const mongoose = require('mongoose');

const reviewSectionSchema = new mongoose.Schema({
  reviewId: { type: String, required: true, index: true },
  key:      { type: String, required: true },
  data:     [mongoose.Schema.Types.Mixed],
});

// Unique per review + section key, enables safe upserts
reviewSectionSchema.index({ reviewId: 1, key: 1 }, { unique: true });

module.exports = mongoose.model('ReviewSection', reviewSectionSchema);
