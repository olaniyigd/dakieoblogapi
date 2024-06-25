const mongoose = require('mongoose');

const walletSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    availableBalance: { type: Number, required: true, default: 0 },
    balance: { type: Number, required: true, default: 0 },
    transactions: [{
        type: {
            type: String,
            enum: ['credit', 'debit'],
            required: true
        },
        amount: {
            type: Number,
            required: true
        },
        date: {
            type: Date,
            default: Date.now
        },
        description: {
            type: String
        }
    }]
});

const Wallet = mongoose.model('Wallet', walletSchema);

module.exports = Wallet;
