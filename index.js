const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const User = require('./User'); // Import the User model
const Wallet = require('./wallet'); // Import the Wallet model

dotenv.config();
const app = express();

app.use(express.json());

const mongoURI = "mongodb+srv://dakieopay:dakieopay@cluster2.fbdblql.mongodb.net/";
const jwtSecret = "olaniyi";
const resetPasswordTokenSecret = "inioluwa";

if (!jwtSecret || !resetPasswordTokenSecret) {
    console.error("JWT_SECRET or RESET_PASSWORD_TOKEN_SECRET is not defined in environment variables.");
    process.exit(1); // Exit the application if JWT_SECRET or RESET_PASSWORD_TOKEN_SECRET is not defined
}

mongoose.connect(mongoURI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => {
        console.log('Connected to MongoDB');
    })
    .catch(err => {
        console.error('Error connecting to MongoDB:', err.message);
    });

app.get('/', (req, res) => {
    res.send('Hello World!');
});

app.post('/signup', async (req, res) => {
    const { username, email, phoneNumber, password } = req.body;

    if (!username || !email || !phoneNumber || !password) {
        return res.status(400).json({ message: {username:"username is required", email:"email is required", phoneNumber:"phone number is required and it must be a number", password:"password is required"} });
    }

    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'Email already in use', statusCode:"400" });
        }

        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        const newUser = new User({ username, email, phoneNumber, password: hashedPassword });
        await newUser.save();

        const newWallet = new Wallet({ userId: newUser._id });
        await newWallet.save();

        res.status(201).json({ message: 'User created successfully', statusCode:"201" });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message, statusCode:"500" });
    }
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    // Validate the input
    if (!email || !password) {
        return res.status(400).json({ message: {email:"email is required", password:"password is required"} });
    }

    try {
        // Check if the user exists
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'Invalid email or password', statusCode:"400" });
        }

        // Compare the password with the stored hashed password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid email or password', statusCode:"400" });
        }

        // Generate a token
        const token = jwt.sign({ id: user._id }, jwtSecret, { expiresIn: '1h' });

        res.status(200).json({
            token,
            user: {
                id: user._id,
                username: user.username,
                email: user.email
            },
            statusCode:"200"
        });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message, statusCode:"500" });
    }
});

// Middleware to authenticate token
const authenticateToken = (req, res, next) => {
    const token = req.header('Authorization')?.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, jwtSecret, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// Get wallet details by userId
app.get('/wallet/:userId', authenticateToken, async (req, res) => {
    try {
        const wallet = await Wallet.findOne({ userId: req.params.userId });
        if (!wallet) {
            return res.status(404).json({ message: 'Wallet not found', statusCode:"404" });
        }
        res.status(200).json({ wallet, statusCode:"200" });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message, statusCode:"500" });
    }
});

// Add to available balance
app.post('/wallet/:userId/balance', authenticateToken, async (req, res) => {
    const { availableBalance } = req.body;
    if (typeof availableBalance !== 'number') {
        return res.status(400).json({ message: 'Available balance must be a number', statusCode:"400" });
    }

    try {
        const wallet = await Wallet.findOne({ userId: req.params.userId });
        if (!wallet) {
            return res.status(404).json({ message: 'Wallet not found', statusCode:"404" });
        }
        wallet.availableBalance += availableBalance;
        await wallet.save();
        res.status(200).json({ message: 'Available balance added successfully', statusCode:"200" });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message, statusCode:"500" });
    }
});

// Deduct from available balance
app.post('/wallet/:userId/balance/deduct', authenticateToken, async (req, res) => {
    const { availableBalance } = req.body;
    if (typeof availableBalance !== 'number') {
        return res.status(400).json({ message: 'Available balance must be a number', statusCode:"400" });
    }

    try {
        const wallet = await Wallet.findOne({ userId: req.params.userId });
        if (!wallet) {
            return res.status(404).json({ message: 'Wallet not found', statusCode:"404" });
        }
        if (wallet.availableBalance < availableBalance) {
            return res.status(400).json({ message: 'Insufficient balance', statusCode:"400" });
        }
        wallet.availableBalance -= availableBalance;
        await wallet.save();
        res.status(200).json({ message: 'Available balance deducted successfully', statusCode:"200" });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message, statusCode:"500" });
    }
});

// Change user password
app.post('/change-password', authenticateToken, async (req, res) => {
    const { currentPassword, newPassword } = req.body;

    // Validate input
    if (!currentPassword || !newPassword) {
        return res.status(400).json({ message: 'Current password and new password are required', statusCode:"400" });
    }

    try {
        const user = await User.findById(req.user.id);
        if (!user) {
            return res.status(404).json({ message: 'User not found', statusCode:"404" });
        }

        // Compare current password with stored hashed password
        const isMatch = await bcrypt.compare(currentPassword, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Current password is incorrect', statusCode:"400" });
        }

        // Hash and salt the new password
        const saltRounds = 10;
        const hashedNewPassword = await bcrypt.hash(newPassword, saltRounds);

        // Update user's password
        user.password = hashedNewPassword;
        await user.save();

        res.status(200).json({ message: 'Password updated successfully', statusCode:"200" });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message, statusCode:"500" });
    }
});

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'prodesmond43@gmail.com',
        pass: 'Tifemi3423'
    }
});

// Request password reset
app.post('/request-password-reset', async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ message: 'Email is required', statusCode:"400" });
    }

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: 'User not found', statusCode:"404" });
        }

        const resetToken = crypto.randomBytes(32).toString('hex');
        const hashedResetToken = await bcrypt.hash(resetToken, 10);

        user.resetPasswordToken = hashedResetToken;
        user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
        await user.save();

        // Send email with reset token
        const mailOptions = {
            from: 'prodesmond43@gmail.com',
            to: email,
            subject: 'Password Reset',
            text: `Here is your password reset token: ${resetToken}`
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error('Error sending email:', error);
                return res.status(500).json({ message: 'Error sending email', error: error.message, statusCode:"500" });
            }
            console.log('Email sent:', info.response);
            res.status(200).json({ message: 'Password reset token generated and sent via email', statusCode:"200" });
        });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message, statusCode:"500" });
    }
});


// Reset password
app.post('/reset-password', async (req, res) => {
    const { email, token, newPassword } = req.body;

    if (!email || !token || !newPassword) {
        return res.status(400).json({ message: 'Email, token, and new password are required', statusCode:"400" });
    }

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: 'User not found', statusCode:"404" });
        }

        const isTokenValid = await bcrypt.compare(token, user.resetPasswordToken);
        if (!isTokenValid || user.resetPasswordExpires < Date.now()) {
            return res.status(400).json({ message: 'Invalid or expired token', statusCode:"400" });
        }

        // Hash and salt the new password
        const saltRounds = 10;
        const hashedNewPassword = await bcrypt.hash(newPassword, saltRounds);

        // Update user's password and clear the reset token fields
        user.password = hashedNewPassword;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        await user.save();

        res.status(200).json({ message: 'Password reset successfully', statusCode:"200" });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message, statusCode:"500" });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server started at port ${PORT}`);
});
