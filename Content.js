const mongoose = require('mongoose');

const contentSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    text: { type: String, required: true },
    imagePath: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});

const Content = mongoose.model('Content', contentSchema);

module.exports = Content;
