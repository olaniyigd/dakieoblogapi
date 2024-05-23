const mongoose = require('mongoose');

const walletSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    availableBalance: { type: Number, required: true, default: 0 },
    balance: { type: Number, required: true, default: 0 },
});

const Wallet = mongoose.model('Wallet', walletSchema);

module.exports = Wallet;
