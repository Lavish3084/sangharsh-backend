require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
app.use(cors());
app.use(bodyParser.json()); // Parse JSON body

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log('✅ Connected to MongoDB'))
  .catch(err => console.log('❌ MongoDB Connection Error:', err));

// Define Feedback Model
const Feedback = mongoose.model('Feedback', new mongoose.Schema({
    name: String,
    email: String,
    feedback: String,
    date: { type: Date, default: Date.now }
}));

// Middleware to log all requests
app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
    next();
});

// API Route to Submit Feedback
app.post('/feedback', async (req, res) => {
    console.log('Body:', req.body);  // Log request body
    try {
        const newFeedback = new Feedback(req.body);
        await newFeedback.save();
        res.status(201).json({ message: "✅ Feedback submitted successfully!" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// API Route to Retrieve All Feedbacks
app.get('/feedbacks', async (req, res) => {
    try {
        const feedbacks = await Feedback.find();
        res.json(feedbacks);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Handle undefined routes
app.use((req, res) => {
    res.status(404).json({ error: "❌ Route not found!" });
});

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
