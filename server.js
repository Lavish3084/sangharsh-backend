require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const twilio = require('twilio');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const http = require('http');
const socketIo = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

const PORT = process.env.PORT || 5001;

// Twilio Configuration
const TWILIO_ACCOUNT_SID = process.env.TWILIO_ACCOUNT_SID;
const TWILIO_AUTH_TOKEN = process.env.TWILIO_AUTH_TOKEN;
const TWILIO_VERIFY_SERVICE_SID = process.env.TWILIO_VERIFY_SERVICE_SID;
const JWT_SECRET = process.env.JWT_SECRET;

// Create Twilio client with error handling
const twilioClient = twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN);

// Configure multer for file uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});

const upload = multer({ 
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
    fileFilter: function (req, file, cb) {
        if (!file.originalname.match(/\.(jpg|jpeg|png|gif)$/)) {
            return cb(new Error('Only image files are allowed!'), false);
        }
        cb(null, true);
    }
});

// Create uploads directory if it doesn't exist
if (!fs.existsSync('uploads')) {
    fs.mkdirSync('uploads');
}

// Serve static files from uploads directory
app.use('/uploads', express.static('uploads'));

// Middleware
app.use(bodyParser.json());
app.use(cors());

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log('Connected to MongoDB'))
    .catch(err => console.error('MongoDB connection error:', err));

// Labor Schema and Model
const laborSchema = new mongoose.Schema({
    name: { type: String, required: true },
    skill: { type: String, required: true },
    availability_status: { type: String, enum: ["Available", "Busy"], default: "Available" },
    location: { type: String, required: true },
    rating: { type: Number, default: 0 },
    pricePerDay: { type: Number, required: true },
    imageUrl: { type: String, required: true },
    category: { type: String, required: true },
    specialization: { type: String },
    experience: { type: Number },
    isBookmarked: { type: Boolean, default: false },
    registeredAt: { type: Date, default: Date.now }
});

const Labor = mongoose.model('Labor', laborSchema);

// Booking Schema and Model
const bookingSchema = new mongoose.Schema({
    user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    labor_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Labor', required: true },
    status: { type: String, enum: ["Pending", "Confirmed", "Rejected", "Completed"], default: "Pending" },
    amount: { type: Number, required: true },
    start_time: { type: Date, required: true },
    end_time: { type: Date, required: true },
    createdAt: { type: Date, default: Date.now }
});

const Booking = mongoose.model('Booking', bookingSchema);

// Define Feedback Model
const Feedback = mongoose.model('Feedback', new mongoose.Schema({
    name: String,
    email: String,
    feedback: String,
    date: { type: Date, default: Date.now }
}));

// Define User Feedback Model
const UserFeedback = mongoose.model('UserFeedback', new mongoose.Schema({
    name: String,
    email: String,
    feedback: String,
    date: { type: Date, default: Date.now }
}));

// User Schema
const UserSchema = new mongoose.Schema({
    fullName: { type: String, required: true },
    phoneNumber: { type: String },
    email: { type: String, sparse: true },
    idType: { type: String, enum: ['PAN', 'Aadhar', 'Voter ID', 'Driving License'] },
    idProofPath: { type: String },
    isVerified: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now },
    googleId: { type: String, sparse: true },
    profilePicture: { type: String }
});

const User = mongoose.model("User", UserSchema);

// OTP Schema
const OTPSchema = new mongoose.Schema({
    phoneNumber: { type: String, required: true },
    otp: { type: String, required: true },
    createdAt: { type: Date, default: Date.now, expires: 300 } // OTP expires after 5 minutes
});

const OTP = mongoose.model("OTP", OTPSchema);

// Generate OTP
function generateOTP() {
    return Math.floor(1000 + Math.random() * 9000).toString();
}

// Update the sendOTP function
async function sendOTP(phoneNumber) {
    try {
        console.log(`📱 Requesting verification for ${phoneNumber}`);
        
        // Use Twilio Verify to send the verification code
        const verification = await twilioClient.verify.v2
            .services(TWILIO_VERIFY_SERVICE_SID)
            .verifications.create({
                to: phoneNumber,
                channel: 'sms'
            });
        
        console.log(`Verification status: ${verification.status}`);
        return verification.status === 'pending';
    } catch (error) {
        console.error('Error sending verification via Twilio:', error);
        return false;
    }
}

// Add a new function to check verification code
async function verifyOTP(phoneNumber, code) {
    try {
        const verificationCheck = await twilioClient.verify.v2
            .services(TWILIO_VERIFY_SERVICE_SID)
            .verificationChecks.create({
                to: phoneNumber,
                code: code
            });

        return verificationCheck.status === 'approved';
    } catch (error) {
        console.error('Error checking verification code:', error);
        return false;
    }
}

// Middleware to verify JWT token
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: 'Access token required' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid or expired token' });
        req.user = user;
        next();
    });
}

// Middleware to log all requests
app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
    next();
});

// POST API - Register a new labor
app.post('/api/labors/register', async (req, res) => {
    try {
        console.log('Received data:', req.body); // Log the incoming data
        const {
            name,
            location,
            skill,
            pricePerDay,
            imageUrl,
            category,
            specialization,
            experience,
            phoneNumber, // Include phoneNumber
            isBookmarked
        } = req.body;

        // Basic validation
        if (!name || !location || !pricePerDay || !imageUrl || !category || !skill || !phoneNumber) {
            return res.status(400).json({
                error: 'Name, location, pricePerDay, imageUrl, category, skill, and phoneNumber are required'
            });
        }

        // Create a new labor using the mongoose model
        const newLabor = new Labor({
            name,
            location,
            skill,
            pricePerDay,
            imageUrl,
            category,
            specialization,
            experience,
            mobile_number: phoneNumber,
            isBookmarked: isBookmarked || false
        });

        // Save to MongoDB
        await newLabor.save();

        res.status(201).json({
            message: 'Labor registered successfully',
            labor: newLabor
        });
    } catch (error) {
        console.error('Error saving labor:', error);
        res.status(500).json({ error: 'Server error', details: error.message });
    }
});

// GET API - Retrieve all labors
app.get('/api/labors', async (req, res) => {
    try {
        const labors = await Labor.find();
        res.status(200).json(labors);
    } catch (error) {
        res.status(500).json({ error: 'Server error', details: error.message });
    }
});

// GET API - Retrieve a specific labor by ID
app.get('/api/labors/:id', async (req, res) => {
    try {
        const labor = await Labor.findById(req.params.id);

        if (!labor) {
            return res.status(404).json({ error: 'Labor not found' });
        }

        res.status(200).json(labor);
    } catch (error) {
        res.status(500).json({ error: 'Server error', details: error.message });
    }
});

// API Route to Submit Feedback
app.post('/api/laborsfeedback', async (req, res) => {
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
app.get('/api/labors/feedbacks', async (req, res) => {
    try {
        const feedbacks = await Feedback.find();
        res.json(feedbacks);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// API Route to Submit User Feedback
app.post('/api/users/feedback', async (req, res) => {
    console.log('Body:', req.body);  // Log request body
    try {
        const newUserFeedback = new UserFeedback(req.body);
        await newUserFeedback.save();
        res.status(201).json({ message: "✅ User feedback submitted successfully!" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// API Route to Retrieve All User Feedbacks
app.get('/api/users/feedbacks', async (req, res) => {
    try {
        const userFeedbacks = await UserFeedback.find();
        res.json(userFeedbacks);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Update the request-otp endpoint
app.post('/api/labors/auth/request-otp', async (req, res) => {
    try {
        const { phoneNumber } = req.body;
        
        if (!phoneNumber) {
            return res.status(400).json({ error: 'Phone number is required' });
        }
        
        // Send verification request via Twilio Verify
        const sent = await sendOTP(phoneNumber);
        
        if (sent) {
            return res.status(200).json({ 
                message: 'Verification code sent successfully'
            });
        } else {
            return res.status(500).json({ error: 'Failed to send verification code' });
        }
    } catch (error) {
        console.error('❌ Error requesting verification:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Update verify-otp endpoint
app.post('/api/labors/auth/verify-otp', async (req, res) => {
    try {
        const { phoneNumber, otp } = req.body;
        
        if (!phoneNumber || !otp) {
            return res.status(400).json({ error: 'Phone number and verification code are required' });
        }
        
        // Verify the code with Twilio
        const isValid = await verifyOTP(phoneNumber, otp);
        
        if (!isValid) {
            return res.status(400).json({ error: 'Invalid verification code' });
        }
        
        // Find or create user
        let user = await User.findOne({ phoneNumber });
        
        if (!user) {
            // Create a new unverified user if not exists
            user = new User({
                fullName: `User-${phoneNumber.slice(-4)}`,
                phoneNumber,
                isVerified: false
            });
            await user.save();
        }
        
        // Mark user as verified
        user.isVerified = true;
        await user.save();
        
        // Generate JWT token
        const token = jwt.sign(
            { id: user._id, phoneNumber: user.phoneNumber },
            JWT_SECRET,
            { expiresIn: '7d' }
        );
        
        res.status(200).json({
            message: 'Phone number verified successfully',
            token,
            user: {
                id: user._id,
                fullName: user.fullName,
                phoneNumber: user.phoneNumber,
                isVerified: user.isVerified,
                profilePicture: user.profilePicture
            }
        });
    } catch (error) {
        console.error('❌ Error verifying code:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Sign up
app.post('/api/labors/auth/signup', upload.single('idProof'), async (req, res) => {
    try {
        const { fullName, phoneNumber, idType } = req.body;

        // Validate required fields
        if (!fullName || !phoneNumber || !idType) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        // Check if user already exists
        const existingUser = await User.findOne({ phoneNumber });

        if (existingUser && existingUser.isVerified) {
            return res.status(400).json({ error: 'User already exists with this phone number' });
        }

        let user;
        let idProofPath = null;

        // If ID proof was uploaded
        if (req.file) {
            idProofPath = req.file.path;
        }

        if (existingUser) {
            // Update existing user
            existingUser.fullName = fullName;
            existingUser.idType = idType;
            if (idProofPath) existingUser.idProofPath = idProofPath;
            user = await existingUser.save();
        } else {
            // Create new user
            user = new User({
                fullName,
                phoneNumber,
                idType,
                idProofPath,
                isVerified: false
            });
            await user.save();
        }

        // Send verification request
        const sent = await sendOTP(phoneNumber);

        if (!sent) {
            return res.status(500).json({ error: 'Failed to send verification code' });
        }

        res.status(201).json({
            message: 'User created successfully. Please verify your phone number with the code sent.',
            userId: user._id
        });
    } catch (error) {
        console.error('❌ Error in signup:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Google Sign In
app.post('/api/labors/auth/google', async (req, res) => {
    try {
        const { googleId, email, fullName, profilePicture } = req.body;

        if (!googleId || !email) {
            return res.status(400).json({ error: 'Google ID and email are required' });
        }

        // Find or create user
        let user = await User.findOne({ googleId });

        if (!user) {
            // Check if user exists with this email
            user = await User.findOne({ email });

            if (user) {
                // Update existing user with Google info
                user.googleId = googleId;
                user.profilePicture = profilePicture || user.profilePicture;
            } else {
                // Create new user
                user = new User({
                    fullName,
                    email,
                    googleId,
                    profilePicture,
                    isVerified: true,
                    phoneNumber: `google-${Date.now()}` // Placeholder, should be updated later
                });
            }

            await user.save();
        }

        try {
            // Ensure JWT_SECRET is defined
            if (!JWT_SECRET) {
                throw new Error("Missing JWT_SECRET");
            }

            // Generate JWT token
            const token = jwt.sign(
                { id: user._id, email: user.email },
                JWT_SECRET,
                { expiresIn: '7d' }
            );

            res.status(200).json({
                message: 'Google sign-in successful',
                token,
                user: {
                    id: user._id,
                    fullName: user.fullName,
                    email: user.email,
                    phoneNumber: user.phoneNumber,
                    isVerified: user.isVerified,
                    profilePicture: user.profilePicture
                }
            });
        } catch (error) {
            console.error('❌ Error in Google sign-in:', error.message);
            res.status(500).json({ error: 'Internal server error' });
        }
    } catch (error) {
        console.error('❌ Error in Google sign-in:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get user profile
app.get('/api/user/profile', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-__v');

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.status(200).json({
            user: {
                id: user._id,
                fullName: user.fullName,
                phoneNumber: user.phoneNumber,
                email: user.email,
                idType: user.idType,
                isVerified: user.isVerified,
                profilePicture: user.profilePicture,
                createdAt: user.createdAt
            }
        });
    } catch (error) {
        console.error('❌ Error fetching user profile:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Update user profile
app.put('/api/user/profile', authenticateToken, upload.single('profilePicture'), async (req, res) => {
    try {
        const { fullName, phoneNumber, email } = req.body;

        const user = await User.findById(req.user.id);

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Update fields if provided
        if (fullName) user.fullName = fullName;
        if (phoneNumber) user.phoneNumber = phoneNumber;
        if (email) user.email = email;

        // Update profile picture if uploaded
        if (req.file) {
            user.profilePicture = req.file.path;
        }

        await user.save();

        res.status(200).json({
            message: 'Profile updated successfully',
            user: {
                id: user._id,
                fullName: user.fullName,
                phoneNumber: user.phoneNumber,
                email: user.email,
                isVerified: user.isVerified,
                profilePicture: user.profilePicture
            }
        });
    } catch (error) {
        console.error('❌ Error updating user profile:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Message Schema
const MessageSchema = new mongoose.Schema({
    text: String,
    senderName: String,
    timestamp: String,
    roomId: String,
    receiverName: String,
    imageUrl: String,
    isRead: {
        type: Boolean,
        default: false
    }
});

const Message = mongoose.model("Message", MessageSchema);

// WebSocket Connection with Error Handling
io.on("connection", (socket) => {
    console.log("✅ User Connected:", socket.id);

    // Handle joining a specific chat room
    socket.on("joinRoom", (roomId) => {
        socket.join(roomId);
        console.log(`User ${socket.id} joined room ${roomId}`); // ✅ Fixed template literal
    });

    // Handle incoming messages
    socket.on("sendMessage", async (data) => {
        try {
            // Save message to database
            const newMessage = new Message(data);
            await newMessage.save();

            // If roomId is provided, emit to that room only
            if (data.roomId) {
                io.to(data.roomId).emit("newMessage", data);
                console.log(`Message sent to room ${data.roomId}`); // ✅ Fixed template literal
            } else {
                // Otherwise broadcast to everyone (fallback)
                io.emit("newMessage", data);
                console.log("Message broadcast to all users (no room specified)");
            }
        } catch (error) {
            console.error("❌ Error saving message:", error);
            // Notify sender of error
            socket.emit("messageError", { error: "Failed to save message" });
        }
    });

    // Handle message read status updates
    socket.on("markAsRead", async ({ messageId }) => {
        try {
            await Message.findByIdAndUpdate(messageId, { isRead: true });
            socket.broadcast.emit("messageRead", { messageId });
        } catch (error) {
            console.error("❌ Error marking message as read:", error);
        }
    });

    // Handle unexpected disconnects
    socket.on("disconnect", (reason) => {
        console.log(`⚠ User Disconnected: ${socket.id} (Reason: ${reason})`);
    });

    // Handle errors in socket connection
    socket.on("error", (error) => {
        console.error(`❌ Socket Error: ${error.message || error}`);
    });
});

// API endpoint to get messages for a specific room
app.get('/api/messages', async (req, res) => {
    try {
        const { roomId } = req.query;

        // Build query based on roomId if provided
        let query = {};
        if (roomId) {
            query.roomId = roomId;
        }

        // Get messages sorted by timestamp
        const messages = await Message.find(query).sort({ timestamp: 1 });

        console.log(`Retrieved ${messages.length} messages for room ${roomId || 'all'}`);
        res.json(messages);

    } catch (error) {
        console.error('❌ Error fetching messages:', error);
        res.status(500).json({ error: 'Failed to fetch messages' });
    }
});

// API endpoint to delete messages
app.delete('/api/messages/:id', async (req, res) => {
    try {
        await Message.findByIdAndDelete(req.params.id);
        res.status(200).json({ message: 'Message deleted successfully' });
    } catch (error) {
        console.error('❌ Error deleting message:', error);
        res.status(500).json({ error: 'Failed to delete message' });
    }
});

// API endpoint to get all chat rooms
app.get('/api/rooms', async (req, res) => {
    try {
        // Get distinct roomIds
        const rooms = await Message.distinct('roomId');
        res.json(rooms.filter(room => room)); // Filter out null/undefined
    } catch (error) {
        console.error('❌ Error fetching rooms:', error);
        res.status(500).json({ error: 'Failed to fetch rooms' });
    }
});

// Update Labor Availability
app.patch('/api/labors/:id/availability', async (req, res) => {
    try {
        const { availability_status } = req.body;
        if (!["Available", "Busy"].includes(availability_status)) {
            return res.status(400).json({ error: "Invalid availability status" });
        }

        const labor = await Labor.findByIdAndUpdate(
            req.params.id,
            { availability_status },
            { new: true }
        );

        if (!labor) {
            return res.status(404).json({ error: "Labor not found" });
        }

        res.json({ 
            message: "Availability updated successfully",
            labor 
        });
    } catch (error) {
        console.error('❌ Error updating availability:', error);
        res.status(500).json({ error: "Failed to update availability" });
    }
});

// Get Booking Requests for a Labor
app.get('/api/bookings/labor/:laborId', async (req, res) => {
    try {
        const bookings = await Booking.find({ 
            labor_id: req.params.laborId, 
            status: "Pending" 
        }).populate('user_id', 'fullName phoneNumber');

        res.json(bookings);
    } catch (error) {
        console.error('❌ Error fetching bookings:', error);
        res.status(500).json({ error: "Failed to fetch bookings" });
    }
});

// Accept Booking
app.patch('/api/bookings/:bookingId/accept', async (req, res) => {
    try {
        const booking = await Booking.findById(req.params.bookingId);

        if (!booking) {
            return res.status(404).json({ error: "Booking not found" });
        }

        if (booking.status !== "Pending") {
            return res.status(400).json({ error: "Booking is not in pending status" });
        }

        // Update booking status
        booking.status = "Confirmed";
        await booking.save();

        // Update labor availability
        await Labor.findByIdAndUpdate(booking.labor_id, { availability_status: "Busy" });

        res.json({ 
            message: "Booking accepted successfully",
            booking 
        });
    } catch (error) {
        console.error('❌ Error accepting booking:', error);
        res.status(500).json({ error: "Failed to accept booking" });
    }
});

// Reject Booking
app.patch('/api/bookings/:bookingId/reject', async (req, res) => {
    try {
        const booking = await Booking.findById(req.params.bookingId);

        if (!booking) {
            return res.status(404).json({ error: "Booking not found" });
        }

        if (booking.status !== "Pending") {
            return res.status(400).json({ error: "Booking is not in pending status" });
        }

        booking.status = "Rejected";
        await booking.save();

        res.json({ 
            message: "Booking rejected successfully",
            booking 
        });
    } catch (error) {
        console.error('❌ Error rejecting booking:', error);
        res.status(500).json({ error: "Failed to reject booking" });
    }
});

// Complete Booking
app.patch('/api/bookings/:bookingId/complete', async (req, res) => {
    try {
        const booking = await Booking.findById(req.params.bookingId);

        if (!booking) {
            return res.status(404).json({ error: "Booking not found" });
        }

        if (booking.status !== "Confirmed") {
            return res.status(400).json({ error: "Booking is not in confirmed status" });
        }

        booking.status = "Completed";
        await booking.save();

        // Update labor availability back to available
        await Labor.findByIdAndUpdate(booking.labor_id, { availability_status: "Available" });

        res.json({ 
            message: "Booking completed successfully",
            booking 
        });
    } catch (error) {
        console.error('❌ Error completing booking:', error);
        res.status(500).json({ error: "Failed to complete booking" });
    }
});

// Create new booking
app.post('/api/bookings', authenticateToken, async (req, res) => {
    try {
        const { labor_id, amount, start_time, end_time } = req.body;

        // Validate required fields
        if (!labor_id || !amount || !start_time || !end_time) {
            return res.status(400).json({ error: "All fields are required" });
        }

        // Check if labor exists and is available
        const labor = await Labor.findById(labor_id);
        if (!labor) {
            return res.status(404).json({ error: "Labor not found" });
        }
        if (labor.availability_status !== "Available") {
            return res.status(400).json({ error: "Labor is not available" });
        }

        // Create new booking
        const booking = new Booking({
            user_id: req.user.id,
            labor_id,
            amount,
            start_time,
            end_time,
            status: "Pending"
        });

        await booking.save();

        res.status(201).json({
            message: "Booking created successfully",
            booking
        });
    } catch (error) {
        console.error('❌ Error creating booking:', error);
        res.status(500).json({ error: "Failed to create booking" });
    }
});

// Get user's bookings
app.get('/api/bookings/user', authenticateToken, async (req, res) => {
    try {
        const bookings = await Booking.find({ user_id: req.user.id })
            .populate('labor_id', 'name location pricePerDay')
            .sort({ createdAt: -1 });

        res.json(bookings);
    } catch (error) {
        console.error('❌ Error fetching user bookings:', error);
        res.status(500).json({ error: "Failed to fetch bookings" });
    }
});

// Request Schema and Model
const requestSchema = new mongoose.Schema({
    name: { type: String, required: true },
    location: { type: String, required: true },
    requestId: { type: String, required: true, unique: true },
    from: { type: String, required: true },
    requestOn: { type: Date, required: true },
    acceptBefore: { type: Date, required: true },
    offeredAmount: { type: Number, required: true },
    workingHours: { type: Number, required: true },
    status: { type: String, enum: ["Pending", "Accepted", "Rejected", "Completed"], default: "Pending" },
    createdAt: { type: Date, default: Date.now }
});

const Request = mongoose.model('Request', requestSchema);

// Negotiation Schema and Model
const negotiationSchema = new mongoose.Schema({
    requestId: { type: String, required: true, ref: 'Request' },
    currentAmount: { type: Number, required: true },
    negotiatedAmount: { type: Number },
    status: { 
        type: String, 
        enum: ["Pending", "Accepted", "Rejected", "Negotiating"], 
        default: "Pending" 
    },
    negotiationHistory: [{
        amount: Number,
        status: String,
        timestamp: { type: Date, default: Date.now }
    }],
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

const Negotiation = mongoose.model('Negotiation', negotiationSchema);

// GET API - Get negotiation details for a request
app.get('/api/negotiate/:requestId', async (req, res) => {
    try {
        const { requestId } = req.params;

        // Find the request first
        const request = await Request.findOne({ requestId });
        if (!request) {
            return res.status(404).json({
                success: false,
                error: 'Request not found'
            });
        }

        // Find or create negotiation record
        let negotiation = await Negotiation.findOne({ requestId });

        if (!negotiation) {
            // Create new negotiation record if it doesn't exist
            negotiation = new Negotiation({
                requestId,
                currentAmount: request.offeredAmount,
                status: "Pending"
            });
            await negotiation.save();
        }

        res.status(200).json({
            success: true,
            request: {
                name: request.name,
                location: request.location,
                workingHours: request.workingHours
            },
            negotiation: {
                currentAmount: negotiation.currentAmount,
                negotiatedAmount: negotiation.negotiatedAmount,
                status: negotiation.status,
                negotiationHistory: negotiation.negotiationHistory
            }
        });
    } catch (error) {
        console.error('❌ Error fetching negotiation details:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch negotiation details',
            details: error.message
        });
    }
});

// POST API - Update negotiation status and amount
app.post('/api/negotiate/:requestId', async (req, res) => {
    try {
        const { requestId } = req.params;
        const { action, negotiatedAmount } = req.body;

        if (!['accept', 'reject', 'negotiate'].includes(action)) {
            return res.status(400).json({
                success: false,
                error: 'Invalid action. Must be one of: accept, reject, negotiate'
            });
        }

        // Find the request
        const request = await Request.findOne({ requestId });
        if (!request) {
            return res.status(404).json({
                success: false,
                error: 'Request not found'
            });
        }

        // Find or create negotiation record
        let negotiation = await Negotiation.findOne({ requestId });

        if (!negotiation) {
            negotiation = new Negotiation({
                requestId,
                currentAmount: request.offeredAmount,
                status: "Pending"
            });
        }

        // Update negotiation based on action
        switch (action) {
            case 'accept':
                negotiation.status = "Accepted";
                negotiation.negotiationHistory.push({
                    amount: negotiation.currentAmount,
                    status: "Accepted"
                });
                break;

            case 'reject':
                negotiation.status = "Rejected";
                negotiation.negotiationHistory.push({
                    amount: negotiation.currentAmount,
                    status: "Rejected"
                });
                break;

            case 'negotiate':
                if (!negotiatedAmount || negotiatedAmount <= 0) {
                    return res.status(400).json({
                        success: false,
                        error: 'Valid negotiated amount is required'
                    });
                }
                negotiation.status = "Negotiating";
                negotiation.negotiatedAmount = negotiatedAmount;
                negotiation.negotiationHistory.push({
                    amount: negotiatedAmount,
                    status: "Negotiating"
                });
                break;
        }

        negotiation.updatedAt = new Date();
        await negotiation.save();

        res.status(200).json({
            success: true,
            message: `Negotiation ${action}ed successfully`,
            negotiation: {
                currentAmount: negotiation.currentAmount,
                negotiatedAmount: negotiation.negotiatedAmount,
                status: negotiation.status,
                negotiationHistory: negotiation.negotiationHistory
            }
        });

    } catch (error) {
        console.error('❌ Error updating negotiation:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to update negotiation',
            details: error.message
        });
    }
});

// GET API - Get requests with filters
app.get('/api/request', async (req, res) => {
    try {
        const {
            name,
            location,
            requestId,
            from,
            requestOn,
            acceptBefore,
            offeredAmount,
            workingHours
        } = req.query;

        // Build query object based on provided parameters
        const query = {};

        if (name) query.name = { $regex: name, $options: 'i' };
        if (location) query.location = { $regex: location, $options: 'i' };
        if (requestId) query.requestId = requestId;
        if (from) query.from = from;
        if (requestOn) query.requestOn = new Date(requestOn);
        if (acceptBefore) query.acceptBefore = new Date(acceptBefore);
        if (offeredAmount) query.offeredAmount = offeredAmount;
        if (workingHours) query.workingHours = workingHours;

        // Execute query
        const requests = await Request.find(query).sort({ createdAt: -1 });

        res.status(200).json({
            success: true,
            count: requests.length,
            requests
        });
    } catch (error) {
        console.error('❌ Error fetching requests:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch requests',
            details: error.message
        });
    }
});

// State Schema and Model
const stateSchema = new mongoose.Schema({
    name: { type: String, required: true, unique: true },
    cities: [{ type: String }]
});

const State = mongoose.model('State', stateSchema);

// Registration Schema and Model
const registrationSchema = new mongoose.Schema({
    name: { type: String, required: true },
    dateOfBirth: { type: Date, required: true },
    gender: { type: String, required: true, enum: ['Male', 'Female', 'Other'] },
    state: { type: String, required: true },
    city: { type: String, required: true },
    chaukName: { type: String, required: true },
    aadharCard: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});

const Registration = mongoose.model('Registration', registrationSchema);

// GET API - Get all states
app.get('/states', async (req, res) => {
    try {
        const states = await State.find({}, 'name');
        res.status(200).json({
            success: true,
            states: states.map(state => state.name)
        });
    } catch (error) {
        console.error('❌ Error fetching states:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch states',
            details: error.message
        });
    }
});

// GET API - Get cities for a state
app.get('/cities', async (req, res) => {
    try {
        const { state } = req.query;

        if (!state) {
            return res.status(400).json({
                success: false,
                error: 'State parameter is required'
            });
        }

        const stateData = await State.findOne({ name: state });

        if (!stateData) {
            return res.status(404).json({
                success: false,
                error: 'State not found'
            });
        }

        res.status(200).json({
            success: true,
            cities: stateData.cities
        });
    } catch (error) {
        console.error('❌ Error fetching cities:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch cities',
            details: error.message
        });
    }
});

// POST API - Register new user
app.post('/register', upload.single('aadharCard'), async (req, res) => {
    try {
        const {
            name,
            dateOfBirth,
            gender,
            state,
            city,
            chaukName
        } = req.body;

        // Validate required fields
        if (!name || !dateOfBirth || !gender || !state || !city || !chaukName) {
            return res.status(400).json({
                success: false,
                error: 'All fields are required'
            });
        }

        // Validate gender
        if (!['Male', 'Female', 'Other'].includes(gender)) {
            return res.status(400).json({
                success: false,
                error: 'Invalid gender value'
            });
        }

        // Check if aadhar card file was uploaded
        if (!req.file) {
            return res.status(400).json({
                success: false,
                error: 'Aadhar card file is required'
            });
        }

        // Create new registration
        const registration = new Registration({
            name,
            dateOfBirth: new Date(dateOfBirth),
            gender,
            state,
            city,
            chaukName,
            aadharCard: req.file.path
        });

        await registration.save();

        res.status(201).json({
            success: true,
            message: 'Registration successful',
            registration: {
                id: registration._id,
                name: registration.name,
                dateOfBirth: registration.dateOfBirth,
                gender: registration.gender,
                state: registration.state,
                city: registration.city,
                chaukName: registration.chaukName,
                aadharCard: registration.aadharCard
            }
        });
    } catch (error) {
        console.error('❌ Error in registration:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to register',
            details: error.message
        });
    }
});

// Bank Account Schema and Model
const bankAccountSchema = new mongoose.Schema({
    accountNo: { 
        type: String, 
        required: true,
        unique: true,
        validate: {
            validator: function(v) {
                return /^\d{9,18}$/.test(v); // Bank account numbers are typically 9-18 digits
            },
            message: props => `${props.value} is not a valid account number!` // ✅ Fixed backticks
        }
    },
    branchName: { type: String, required: true },
    ifscCode: { 
        type: String, 
        required: true,
        validate: {
            validator: function(v) {
                return /^[A-Z]{4}0[A-Z0-9]{6}$/.test(v); // IFSC code format validation
            },
            message: props => `${props.value} is not a valid IFSC code!` // ✅ Fixed backticks
        }
    },
    upiId: { 
        type: String,
        validate: {
            validator: function(v) {
                if (!v) return true; // Optional field
                return /^[\w\.\-_]{3,}@[a-zA-Z]{3,}$/.test(v); // Basic UPI ID format validation
            },
            message: props => `${props.value} is not a valid UPI ID!` // ✅ Fixed backticks
        }
    },
    username: { type: String, required: true },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

const BankAccount = mongoose.model('BankAccount', bankAccountSchema);

// POST API - Create bank account details
app.post('/api/bank-account', async (req, res) => {
    try {
        const {
            accountNo,
            branchName,
            ifscCode,
            upiId,
            username
        } = req.body;

        // Validate required fields
        if (!accountNo || !branchName || !ifscCode || !username) {
            return res.status(400).json({
                success: false,
                error: 'Account number, branch name, IFSC code, and username are required'
            });
        }

        // Check if account already exists
        const existingAccount = await BankAccount.findOne({ accountNo });
        if (existingAccount) {
            return res.status(400).json({
                success: false,
                error: 'Bank account with this account number already exists'
            });
        }

        // Create new bank account record
        const bankAccount = new BankAccount({
            accountNo,
            branchName,
            ifscCode,
            upiId,
            username
        });

        await bankAccount.save();

        res.status(201).json({
            success: true,
            message: 'Bank account details saved successfully',
            bankAccount: {
                accountNo: bankAccount.accountNo,
                branchName: bankAccount.branchName,
                ifscCode: bankAccount.ifscCode,
                upiId: bankAccount.upiId,
                username: bankAccount.username
            }
        });
    } catch (error) {
        console.error('❌ Error saving bank account details:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to save bank account details',
            details: error.message
        });
    }
});

// GET API - Get bank account details by username
app.get('/api/bank-account/:username', async (req, res) => {
    try {
        const { username } = req.params;

        if (!username) {
            return res.status(400).json({
                success: false,
                error: 'Username is required'
            });
        }

        const bankAccount = await BankAccount.findOne({ username });

        if (!bankAccount) {
            return res.status(404).json({
                success: false,
                error: 'Bank account details not found for this username'
            });
        }

        res.status(200).json({
            success: true,
            bankAccount: {
                accountNo: bankAccount.accountNo,
                branchName: bankAccount.branchName,
                ifscCode: bankAccount.ifscCode,
                upiId: bankAccount.upiId,
                username: bankAccount.username
            }
        });
    } catch (error) {
        console.error('❌ Error fetching bank account details:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch bank account details',
            details: error.message
        });
    }
});

// Transaction Schema and Model
const transactionSchema = new mongoose.Schema({
    transactionId: { 
        type: String, 
        required: true,
        unique: true,
        default: () => 'TXN' + Date.now() + Math.random().toString(36).substr(2, 5)
    },
    senderName: { 
        type: String, 
        required: true 
    },
    amount: { 
        type: Number, 
        required: true,
        min: [0, 'Amount cannot be negative']
    },
    dateTime: { 
        type: Date, 
        required: true,
        default: Date.now 
    },
    status: { 
        type: String, 
        required: true,
        enum: ['Pending', 'Completed', 'Failed', 'Cancelled'],
        default: 'Pending'
    },
    createdAt: { type: Date, default: Date.now }
});

const Transaction = mongoose.model('Transaction', transactionSchema);

// GET API - Get transactions with filters
app.get('/api/transaction', async (req, res) => {
    try {
        const {
            transactionId,
            senderName,
            amount,
            dateTime,
            status,
            startDate,
            endDate
        } = req.query;

        // Build query object based on provided parameters
        const query = {};

        if (transactionId) query.transactionId = transactionId;
        if (senderName) query.senderName = { $regex: senderName, $options: 'i' }; // Case-insensitive search
        if (amount) query.amount = parseFloat(amount);
        if (status) query.status = status;

        // Handle date range query
        if (startDate || endDate) {
            query.dateTime = {};
            if (startDate) {
                query.dateTime.$gte = new Date(startDate);
            }
            if (endDate) {
                query.dateTime.$lte = new Date(endDate);
            }
        } else if (dateTime) {
            // If specific dateTime is provided
            const specificDate = new Date(dateTime);
            query.dateTime = {
                $gte: new Date(specificDate.setHours(0, 0, 0, 0)),
                $lte: new Date(specificDate.setHours(23, 59, 59, 999))
            };
        }

        // Execute query with pagination
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const skip = (page - 1) * limit;

        const transactions = await Transaction.find(query)
            .sort({ dateTime: -1 }) // Sort by date in descending order
            .skip(skip)
            .limit(limit);

        // Get total count for pagination
        const totalCount = await Transaction.countDocuments(query);

        res.status(200).json({
            success: true,
            currentPage: page,
            totalPages: Math.ceil(totalCount / limit),
            totalTransactions: totalCount,
            count: transactions.length,
            transactions: transactions.map(transaction => ({
                transactionId: transaction.transactionId,
                senderName: transaction.senderName,
                amount: transaction.amount,
                dateTime: transaction.dateTime,
                status: transaction.status,
                createdAt: transaction.createdAt
            }))
        });
    } catch (error) {
        console.error('❌ Error fetching transactions:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch transactions',
            details: error.message
        });
    }
});

// GET API - Get transaction by ID
app.get('/api/transaction/:transactionId', async (req, res) => {
    try {
        const { transactionId } = req.params;

        const transaction = await Transaction.findOne({ transactionId });

        if (!transaction) {
            return res.status(404).json({
                success: false,
                error: 'Transaction not found'
            });
        }

        res.status(200).json({
            success: true,
            transaction: {
                transactionId: transaction.transactionId,
                senderName: transaction.senderName,
                amount: transaction.amount,
                dateTime: transaction.dateTime,
                status: transaction.status,
                createdAt: transaction.createdAt
            }
        });
    } catch (error) {
        console.error('❌ Error fetching transaction:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch transaction',
            details: error.message
        });
    }
});

// GET API - Get transaction history with filters and sorting
app.get('/api/history', async (req, res) => {
    try {
        const {
            startDate,
            endDate,
            status,
            minAmount,
            maxAmount,
            sortBy,
            sortOrder,
            page = 1,
            limit = 20
        } = req.query;

        // Build query object based on provided parameters
        const query = {};

        // Date range filter
        if (startDate || endDate) {
            query.dateTime = {};
            if (startDate) {
                query.dateTime.$gte = new Date(startDate);
            }
            if (endDate) {
                query.dateTime.$lte = new Date(endDate);
            }
        }

        // Status filter
        if (status) {
            if (Array.isArray(status)) {
                query.status = { $in: status };
            } else {
                query.status = status;
            }
        }

        // Amount range filter
        if (minAmount || maxAmount) {
            query.amount = {};
            if (minAmount) {
                query.amount.$gte = parseFloat(minAmount);
            }
            if (maxAmount) {
                query.amount.$lte = parseFloat(maxAmount);
            }
        }

        // Sorting options
        const sortOptions = {};
        if (sortBy) {
            sortOptions[sortBy] = sortOrder === 'desc' ? -1 : 1;
        } else {
            sortOptions.dateTime = -1; // Default sort by date descending
        }

        // Pagination
        const skip = (parseInt(page) - 1) * parseInt(limit);

        // Execute query with pagination and sorting
        const transactions = await Transaction.find(query)
            .sort(sortOptions)
            .skip(skip)
            .limit(parseInt(limit));

        // Get total count and aggregated stats
        const [totalCount, stats] = await Promise.all([
            Transaction.countDocuments(query),
            Transaction.aggregate([
                { $match: query },
                {
                    $group: {
                        _id: null,
                        totalAmount: { $sum: '$amount' },
                        averageAmount: { $avg: '$amount' },
                        minTransactionAmount: { $min: '$amount' },
                        maxTransactionAmount: { $max: '$amount' },
                        completedTransactions: {
                            $sum: { $cond: [{ $eq: ['$status', 'Completed'] }, 1, 0] }
                        },
                        pendingTransactions: {
                            $sum: { $cond: [{ $eq: ['$status', 'Pending'] }, 1, 0] }
                        },
                        failedTransactions: {
                            $sum: { $cond: [{ $eq: ['$status', 'Failed'] }, 1, 0] }
                        }
                    }
                }
            ])
        ]);

        // Group transactions by date
        const groupedTransactions = transactions.reduce((acc, transaction) => {
            const date = transaction.dateTime.toISOString().split('T')[0];
            if (!acc[date]) {
                acc[date] = [];
            }
            acc[date].push({
                transactionId: transaction.transactionId,
                senderName: transaction.senderName,
                amount: transaction.amount,
                dateTime: transaction.dateTime,
                status: transaction.status
            });
            return acc;
        }, {});

        res.status(200).json({
            success: true,
            currentPage: parseInt(page),
            totalPages: Math.ceil(totalCount / parseInt(limit)),
            totalTransactions: totalCount,
            stats: stats.length > 0 ? {
                totalAmount: stats[0].totalAmount,
                averageAmount: stats[0].averageAmount,
                minTransactionAmount: stats[0].minTransactionAmount,
                maxTransactionAmount: stats[0].maxTransactionAmount,
                completedTransactions: stats[0].completedTransactions,
                pendingTransactions: stats[0].pendingTransactions,
                failedTransactions: stats[0].failedTransactions
            } : null,
            history: Object.entries(groupedTransactions).map(([date, transactions]) => ({
                date,
                transactions
            })).sort((a, b) => new Date(b.date) - new Date(a.date))
        });
    } catch (error) {
        console.error('❌ Error fetching transaction history:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch transaction history',
            details: error.message
        });
    }
});

// Temporary route to check environment variables
app.get('/check-env', (req, res) => {
    res.json({
        TWILIO_ACCOUNT_SID: !!process.env.TWILIO_ACCOUNT_SID,
        TWILIO_AUTH_TOKEN: !!process.env.TWILIO_AUTH_TOKEN,
        TWILIO_VERIFY_SERVICE_SID: !!process.env.TWILIO_VERIFY_SERVICE_SID
    });
});

// Update the register worker endpoint
app.post('/api/labors/auth/register', async (req, res) => {
    try {
        const { name, location, skill, pricePerDay, imageUrl, category, specialization, experience, mobile_number } = req.body;

        // Log the incoming data
        console.log('Incoming data:', req.body);

        // Validate required fields
        if (!name || !location || !skill || !pricePerDay || !imageUrl || !category || !mobile_number) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        // Check if mobile_number is null or empty
        if (!mobile_number || mobile_number.trim() === "") {
            return res.status(400).json({ error: 'Mobile number cannot be empty' });
        }

        // Create a new labor using the mongoose model
        const newLabor = new Labor({
            name,
            location,
            skill,
            pricePerDay,
            imageUrl,
            category,
            specialization,
            experience,
            mobile_number, // Save mobile number
            isBookmarked: false // Default value
        });

        // Log the new labor object before saving
        console.log('New labor object:', newLabor);

        // Save to MongoDB
        await newLabor.save();

        res.status(201).json({
            message: 'Worker registered successfully',
            labor: newLabor
        });
    } catch (error) {
        console.error('Error registering worker:', error);
        res.status(500).json({ error: 'Server error', details: error.message });
    }
});

// Start the server
server.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});