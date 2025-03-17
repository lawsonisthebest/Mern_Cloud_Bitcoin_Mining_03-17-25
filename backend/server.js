import express from 'express';
import cors from 'cors';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cron from 'node-cron'; // Import node-cron for scheduling tasks

dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT;
const MONGO_URI = process.env.MONGO_URI;

// Connect to MongoDB
const connectDB = async () => {
    try {
        await mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true });
        console.log("MongoDB connected");
    } catch (error) {
        console.error("Error connecting to MongoDB:", error);
    }
};

// User schema
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    bitcoin: { type: Number, default: 0.0000000000 },
    drivers: { type: Number, default: 0.0000000000 }
});

const User = mongoose.model('User', userSchema);

// Authentication middleware
const authMiddleware = (req, res, next) => {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ message: 'No token provided' });

    try {
        const decoded = jwt.verify(token, process.env.SECRET_KEY);
        req.userId = decoded.id; // Store the user ID in the request object
        next();
    } catch (error) {
        console.error(error);
        res.status(401).json({ message: 'Invalid or expired token' });
    }
};

// Routes

// Signup
app.post('/api/signup', async (req, res) => {
    const { username, password } = req.body;
    try {
        const usernameExists = await User.findOne({ username });
        if (usernameExists) return res.status(400).json({ message: 'Username already registered' });

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username, password: hashedPassword });
        await newUser.save();

        const token = jwt.sign({ id: newUser._id }, process.env.SECRET_KEY, { expiresIn: '1d' });
        res.status(201).json({ message: 'User created successfully', token });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Login
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await User.findOne({ username });
        if (!user) return res.status(400).json({ message: 'Invalid credentials' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

        const token = jwt.sign({ id: user._id }, process.env.SECRET_KEY, { expiresIn: '1d' });
        res.json({ message: 'Login successful', token });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get Bitcoin
app.get('/api/', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.userId);
        if (!user) return res.status(404).json({ message: 'User not found' });

        res.json({ bitcoin: user.bitcoin });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Update Bitcoin
app.patch('/api/', authMiddleware, async (req, res) => {
    const { incrementAmount } = req.body;

    if (typeof incrementAmount !== 'number' || incrementAmount <= 0) {
        return res.status(400).json({ message: 'Invalid increment value' });
    }

    try {
        const user = await User.findById(req.userId);
        if (!user) return res.status(404).json({ message: 'User not found' });

        user.bitcoin += incrementAmount;
        await user.save();

        res.json({ bitcoin: user.bitcoin });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get Drivers
app.get('/api/drivers', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.userId);
        if (!user) return res.status(404).json({ message: 'User not found' });

        res.json({ drivers: user.drivers });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Update Drivers
app.patch('/api/drivers', authMiddleware, async (req, res) => {
    const { incrementAmount } = req.body;

    if (typeof incrementAmount !== 'number' || incrementAmount <= 0) {
        return res.status(400).json({ message: 'Invalid increment value' });
    }

    try {
        const user = await User.findById(req.userId);
        if (!user) return res.status(404).json({ message: 'User not found' });

        user.drivers += incrementAmount;
        await user.save();

        res.json({ drivers: user.drivers });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Task Scheduler (Bitcoin Mining Simulation)
cron.schedule('* * * * *', async () => { // Run every minute
    try {
        const users = await User.find({});
        users.forEach(async (user) => {
            const incrementAmount = user.drivers*60;
            if (incrementAmount > 0) {
                user.bitcoin += incrementAmount;
                await user.save();
            }
        });
    } catch (error) {
        console.error("Error updating Bitcoin:", error);
    }
});

// Start server
app.listen(PORT, () => {
    connectDB();
    console.log(`Server is running on port ${PORT}`);
});
