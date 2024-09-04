const mongoose = require('mongoose');

const contentSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    title: { type: String, required: true },
    description: { type: String, required: true },
    imagePath: { type: String, required: true },
    category: { type: String, enum: ['politics', 'sport', 'entertainment'], required: true },
    createdAt: { type: Date, default: Date.now }
});

const Content = mongoose.model('Content', contentSchema);

module.exports = Content;
