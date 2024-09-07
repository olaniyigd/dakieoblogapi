const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const User = require('./User'); 
const Content = require('./Content'); 

dotenv.config();
const app = express();
const allowedOrigins = ['http://localhost:3000']; // Add your frontend domain here
app.use(cors({
    origin: (origin, callback) => {
        // Allow requests with no origin (e.g. mobile apps or Postman) or check if origin is allowed
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true // If you are using cookies or HTTP authentication
}));


app.use(express.json());
app.use('/uploads', express.static('uploads')); 

const mongoURI = process.env.MONGO_URI;
const jwtSecret = process.env.JWT_SECRET;
const resetPasswordTokenSecret = process.env.RESET_PASSWORD_TOKEN_SECRET;

if (!jwtSecret || !resetPasswordTokenSecret) {
    console.error("JWT_SECRET or RESET_PASSWORD_TOKEN_SECRET is not defined in environment variables.");
    process.exit(1); 
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


        res.status(201).json({ message: 'User created successfully', statusCode:"201" });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message, statusCode:"500" });
    }
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: {email:"email is required", password:"password is required"} });
    }

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'Invalid email or password', statusCode:"400" });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid email or password', statusCode:"400" });
        }

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

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, path.join(__dirname, 'uploads'));
    },
    filename: (req, file, cb) => {
        cb(null, `${Date.now()}-${file.originalname}`);
    }
});
const upload = multer({ storage });

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

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

// Post content with image
app.post('/content', authenticateToken, upload.single('image'), async (req, res) => {
    const { title, description, category } = req.body;

    if (!title || !description || !category || !req.file) {
        return res.status(400).json({ message: 'Title, description, category, and image are required', statusCode: "400" });
    }

    try {
        // Construct the image URL
        const imageUrl = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;

        const newContent = new Content({
            userId: req.user.id,
            title,
            description,
            category,
            imagePath: imageUrl,
            createdAt: Date.now()
        });

        await newContent.save();

        res.status(201).json({ message: 'Content created successfully', statusCode: "201" });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message, statusCode: "500" });
    }
});

// Get all content post without token
app.get('/contents', async (req, res) => {
    try {
        // Find all contents and populate user details (username, email)
        const contents = await Content.find().populate('userId', 'username email');

        // Set topContents as an empty array for testing
        const topContents = await Content.find().sort({ views: -1 }).limit(5);

        // Find the 5 latest contents (sorted by createdAt, descending order)
        const latestContents = await Content.find().sort({ createdAt: -1 }).limit(5);

        // Initialize arrays for each category
        const politicalContents = [];
        const sportContents = [];
        const entertainmentContents = [];

        // Distribute contents into category arrays
        contents.forEach(content => {
            switch (content.category) {
                case 'politics':
                    politicalContents.push(content);
                    break;
                case 'sport':
                    sportContents.push(content);
                    break;
                case 'entertainment':
                    entertainmentContents.push(content);
                    break;
                default:
                    break;
            }
        });

        // Respond with categorized content arrays, including top and latest content
        res.status(200).json({
            topContent: topContents,    // Updated with the most viewed contents
            latest: latestContents,     // The 5 most recent contents based on createdAt
            political: politicalContents,
            sport: sportContents,
            entertainment: entertainmentContents,
            statusCode: "200"
        });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message, statusCode: "500" });
    }
});




// Get single content post (without token)
app.get('/content/:id', async (req, res) => {
    const { id } = req.params;

    try {
        // Find the content by ID and populate user details
        const content = await Content.findById(id).populate('userId', 'username email');
        if (!content) {
            return res.status(404).json({ message: 'Content not found', statusCode: "404" });
        }

        // Increment the view count for the content
        content.views = (content.views || 0) + 1;
        await content.save();

        // Respond with the content
        res.status(200).json({ content, statusCode: "200" });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message, statusCode: "500" });
    }
});


// Update content post
app.put('/content/:id', authenticateToken, upload.single('image'), async (req, res) => {
    const { id } = req.params;
    const { title, description } = req.body;
    const { file } = req;

    if (!title && !description && !file) {
        return res.status(400).json({ message: 'At least one of title, description, or image is required', statusCode: "400" });
    }

    try {
        // Find the content post by ID
        const content = await Content.findById(id);
        if (!content) {
            return res.status(404).json({ message: 'Content not found', statusCode: "404" });
        }

        // Check if the user making the request is the owner of the content
        if (content.userId.toString() !== req.user.id) {
            return res.status(403).json({ message: 'Unauthorized to update this content', statusCode: "403" });
        }

        // Update fields if they are provided
        if (title) content.title = title;
        if (description) content.description = description;
        if (file) {
            // Update the image URL if a new image is uploaded
            content.imagePath = `${req.protocol}://${req.get('host')}/uploads/${file.filename}`;
        }

        await content.save();

        res.status(200).json({ message: 'Content updated successfully', statusCode: "200" });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message, statusCode: "500" });
    }
});


// Delete content post
app.delete('/content/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;

    try {
        // Find the content post by ID
        const content = await Content.findById(id);
        if (!content) {
            return res.status(404).json({ message: 'Content not found', statusCode: "404" });
        }

        // Check if the user making the request is the owner of the content
        if (content.userId.toString() !== req.user.id) {
            return res.status(403).json({ message: 'Unauthorized to delete this content', statusCode: "403" });
        }

        // Optionally, delete the associated image file
        if (content.imagePath) {
            const imagePath = path.join(__dirname, 'uploads', path.basename(content.imagePath));
            fs.unlink(imagePath, (err) => {
                if (err) {
                    console.error('Error deleting the image file:', err.message);
                }
            });
        }

        // Delete the content post
        await Content.findByIdAndDelete(id);

        res.status(200).json({ message: 'Content deleted successfully', statusCode: "200" });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message, statusCode: "500" });
    }
});


// Change password
app.post('/change-password', authenticateToken, async (req, res) => {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
        return res.status(400).json({ message: 'Current password and new password are required', statusCode: "400" });
    }

    try {
        const user = await User.findById(req.user.id);
        if (!user) {
            return res.status(404).json({ message: 'User not found', statusCode: "404" });
        }

        const isMatch = await bcrypt.compare(currentPassword, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Current password is incorrect', statusCode: "400" });
        }

        const saltRounds = 10;
        const hashedNewPassword = await bcrypt.hash(newPassword, saltRounds);

        user.password = hashedNewPassword;
        await user.save();

        res.status(200).json({ message: 'Password updated successfully', statusCode: "200" });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message, statusCode: "500" });
    }
});

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
       user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Request password reset
app.post('/request-password-reset', async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ message: 'Email is required', statusCode: "400" });
    }

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: 'User not found', statusCode: "404" });
        }

        const resetToken = jwt.sign({ id: user._id }, resetPasswordTokenSecret, { expiresIn: '1h' });

        const resetLink = `${req.protocol}://${req.get('host')}/reset-password/${resetToken}`;

        const mailOptions = {
            from: 'dakieopay@gmail.com',
            to: user.email,
            subject: 'Password Reset Request',
            text: `Click on the following link to reset your password: ${resetLink}`,
        };

        await transporter.sendMail(mailOptions);

        res.status(200).json({ message: 'Password reset link sent', statusCode: "200" });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message, statusCode: "500" });
    }
});

// Reset password
app.post('/reset-password/:resetToken', async (req, res) => {
    const { resetToken } = req.params;
    const { newPassword } = req.body;

    if (!newPassword) {
        return res.status(400).json({ message: 'New password is required', statusCode: "400" });
    }

    try {
        const decoded = jwt.verify(resetToken, resetPasswordTokenSecret);
        const user = await User.findById(decoded.id);
        if (!user) {
            return res.status(404).json({ message: 'User not found', statusCode: "404" });
        }

        const saltRounds = 10;
        const hashedNewPassword = await bcrypt.hash(newPassword, saltRounds);

        user.password = hashedNewPassword;
        await user.save();

        res.status(200).json({ message: 'Password reset successfully', statusCode: "200" });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message, statusCode: "500" });
    }
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
