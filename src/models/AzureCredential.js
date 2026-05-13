const mongoose = require('mongoose');

const schema = new mongoose.Schema({
  userId:          { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  label:           { type: String, default: 'Default', trim: true },
  tenantId:        { type: String, required: true },
  clientId:        { type: String, required: true },
  clientSecretEnc: { type: String, required: true },
  subscriptionId:  { type: String, required: true },
  isActive:        { type: Boolean, default: false },
}, { timestamps: true });

module.exports = mongoose.model('AzureCredential', schema);
