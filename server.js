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

const PORT = 5001; // Hardcoded port

// Twilio Configuration
const TWILIO_ACCOUNT_SID = 'AC5bd01490c89f591310cf211e1f8332bb'; // Hardcoded Twilio Account SID
const TWILIO_AUTH_TOKEN = '7ba705521730d02d88f65f23c3e7b40c'; // Hardcoded Twilio Auth Token
const TWILIO_VERIFY_SERVICE_SID = 'VA995eeae047efefde098b40409fa7eb99'; // Hardcoded Twilio Verify Service SID
const JWT_SECRET = 'your-secret-key'; // Hardcoded JWT Secret

// Create Twilio client with error handling
let twilioClient;
try {
    twilioClient = twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN);
    console.log('✅ Twilio client initialized successfully');
} catch (error) {
    console.error('❌ Failed to initialize Twilio client:', error);
    process.exit(1);
}

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
mongoose.connect('mongodb+srv://vmro45:Vmro45%407856@coddunity.kyll8.mongodb.net/sangharsh')
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
    registeredAt: { type: Date, default: Date.now },
    mobile_number: { type: String },
    googleId: { type: String, sparse: true }
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

// Update the sendOTP function with better error handling
async function sendOTP(phoneNumber) {
    try {
        console.log(`📱 Requesting verification for ${phoneNumber}`);
        
        if (!phoneNumber) {
            throw new Error('Phone number is required');
        }

        // Format phone number to E.164 format if not already
        const formattedPhoneNumber = phoneNumber.startsWith('+') ? phoneNumber : `+${phoneNumber}`;
        
        // Use Twilio Verify to send the verification code
        const verification = await twilioClient.verify.v2
            .services(TWILIO_VERIFY_SERVICE_SID)
            .verifications.create({
                to: formattedPhoneNumber,
                channel: 'sms'
            });
        
        console.log(`✅ Verification status: ${verification.status}`);
        return verification.status === 'pending';
    } catch (error) {
        console.error('❌ Error sending verification via Twilio:', error);
        
        // Handle specific Twilio error codes
        if (error.code === 20003) {
            console.error('Authentication failed. Please check your Twilio credentials.');
        } else if (error.code === 21211) {
            console.error('Invalid phone number format.');
        } else if (error.code === 21214) {
            console.error('Phone number is not mobile.');
        }
        
        throw error;
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
        let labor = await Labor.findOne({ mobile_number: phoneNumber });
        
        if (!labor) {
            // Create a new labor if not exists
            labor = new Labor({
                name: `User-${phoneNumber.slice(-4)}`, // Default name
                mobile_number,
                isBookmarked: false // Default value
            });
            await labor.save();
        }
        
        // Generate JWT token
        const token = jwt.sign(
            { id: labor._id, mobile_number: labor.mobile_number },
            JWT_SECRET,
            { expiresIn: '7d' }
        );
        
        res.status(200).json({
            message: 'Phone number verified successfully',
            token,
            labor: {
                id: labor._id,
                name: labor.name,
                skill: labor.skill,
                location: labor.location,
                pricePerDay: labor.pricePerDay,
                imageUrl: labor.imageUrl,
                category: labor.category,
                specialization: labor.specialization,
                experience: labor.experience,
                availability_status: labor.availability_status,
                registeredAt: labor.registeredAt,
                isBookmarked: labor.isBookmarked
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

// User Google Sign In Check
app.get('/api/users/auth/check-google/:googleId', async (req, res) => {
    try {
        const { googleId } = req.params;
        console.log('📥 Checking User Google ID:', googleId);

        // Find user by Google ID
        let user = await User.findOne({ googleId });
        
        if (!user) {
            console.log('❌ No user found with Google ID:', googleId);
            return res.status(404).json({ 
                error: 'User not found',
                exists: false
            });
        }

        // Generate JWT token
        const token = jwt.sign(
            { 
                id: user._id, 
                email: user.email,
                type: 'User'
            },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        console.log('✅ User found with Google ID:', googleId);

        res.status(200).json({
            exists: true,
            token,
            user: {
                id: user._id,
                fullName: user.fullName,
                email: user.email,
                phoneNumber: user.phoneNumber,
                isVerified: user.isVerified,
                profilePicture: user.profilePicture,
                type: 'User'
            }
        });
    } catch (error) {
        console.error('❌ Error checking User Google ID:', error);
        res.status(500).json({ 
            error: 'Internal server error',
            details: error.message
        });
    }
});

// Labor Google Sign In Check
app.get('/api/labors/auth/check-google/:googleId', async (req, res) => {
    try {
        const { googleId } = req.params;
        console.log('📥 Checking Labor Google ID:', googleId);

        if (!googleId) {
            console.error('❌ No Google ID provided');
            return res.status(400).json({
                error: 'Google ID is required',
                exists: false
            });
        }

        // Find labor by Google ID in Labor collection only
        const labor = await Labor.findOne({ googleId: googleId });
        
        if (!labor) {
            console.log('❌ No labor found with Google ID:', googleId);
            return res.status(404).json({ 
                error: 'Labor not found',
                exists: false,
                message: 'No labor account found with this Google ID'
            });
        }

        // Generate JWT token with Labor type
        const token = jwt.sign(
            { 
                id: labor._id, 
                email: labor.email,
                type: 'Labor',
                name: labor.name
            },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        console.log('✅ Labor found with Google ID:', googleId);

        // Return labor details
        res.status(200).json({
            exists: true,
            token,
            labor: {
                id: labor._id,
                name: labor.name,
                email: labor.email,
                mobile_number: labor.mobile_number,
                skill: labor.skill,
                location: labor.location,
                pricePerDay: labor.pricePerDay,
                imageUrl: labor.imageUrl,
                category: labor.category,
                specialization: labor.specialization,
                experience: labor.experience,
                availability_status: labor.availability_status,
                type: 'Labor',
                isVerified: true
            }
        });
    } catch (error) {
        console.error('❌ Error checking Labor Google ID:', error);
        res.status(500).json({ 
            error: 'Internal server error',
            details: error.message,
            exists: false
        });
    }
});

// User Google Sign In
app.post('/api/users/auth/google', async (req, res) => {
    try {
        const { googleId, email, fullName, profilePicture } = req.body;
        console.log('📥 User Google Sign In request:', { googleId, email, fullName });

        if (!googleId || !email) {
            console.error('❌ Missing required fields:', { googleId, email });
            return res.status(400).json({ 
                error: 'Google ID and email are required',
                details: 'Please provide both googleId and email'
            });
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
                user.fullName = fullName || user.fullName;
                console.log('📝 Updating existing user with Google info');
            } else {
                // Create new user with required fields
                user = new User({
                    fullName: fullName || email.split('@')[0], // Use email username if no name provided
                    email,
                    googleId,
                    profilePicture: profilePicture || 'https://via.placeholder.com/150',
                    isVerified: true,
                    phoneNumber: `google-${Date.now()}`, // Placeholder
                    idType: 'Google', // Set default ID type
                    idProofPath: 'google-auth' // Set default proof path
                });
                console.log('📝 Creating new user with Google info');
            }

            await user.save();
        }

        // Generate JWT token
        const token = jwt.sign(
            { 
                id: user._id, 
                email: user.email,
                type: 'User'
            },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        console.log('✅ User Google sign-in successful:', user._id);

        res.status(200).json({
            message: 'Google sign-in successful',
            token,
            user: {
                id: user._id,
                fullName: user.fullName,
                email: user.email,
                phoneNumber: user.phoneNumber,
                isVerified: user.isVerified,
                profilePicture: user.profilePicture,
                type: 'User'
            }
        });
    } catch (error) {
        console.error('❌ Error in User Google sign-in:', error);
        res.status(500).json({ 
            error: 'Internal server error',
            details: error.message
        });
    }
});

// Labor Google Sign In
app.post('/api/labors/auth/google', async (req, res) => {
    try {
        const { googleId, email, name, profilePicture } = req.body;
        console.log('📥 Labor Google Sign In request:', { googleId, email, name });

        if (!googleId || !email) {
            console.error('❌ Missing required fields:', { googleId, email });
            return res.status(400).json({ 
                error: 'Google ID and email are required',
                details: 'Please provide both googleId and email'
            });
        }

        // Find or create labor
        let labor = await Labor.findOne({ googleId });

        if (!labor) {
            // Check if labor exists with this email
            labor = await Labor.findOne({ email });

            if (labor) {
                // Update existing labor with Google info
                labor.googleId = googleId;
                labor.imageUrl = profilePicture || labor.imageUrl;
                console.log('📝 Updating existing labor with Google info');
            } else {
                // Create new labor
                labor = new Labor({
                    name,
                    email,
                    googleId,
                    imageUrl: profilePicture,
                    isVerified: true,
                    mobile_number: `google-${Date.now()}`, // Placeholder
                    availability_status: "Available",
                    skill: "General", // Default skill
                    location: "Not specified", // Default location
                    pricePerDay: 0, // Default price
                    category: "General" // Default category
                });
                console.log('📝 Creating new labor with Google info');
            }

            await labor.save();
        }

        // Generate JWT token
        const token = jwt.sign(
            { 
                id: labor._id, 
                email: labor.email,
                type: 'Labor'
            },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        console.log('✅ Labor Google sign-in successful:', labor._id);

        res.status(200).json({
            message: 'Google sign-in successful',
            token,
            labor: {
                id: labor._id,
                name: labor.name,
                email: labor.email,
                mobile_number: labor.mobile_number,
                skill: labor.skill,
                location: labor.location,
                pricePerDay: labor.pricePerDay,
                imageUrl: labor.imageUrl,
                category: labor.category,
                specialization: labor.specialization,
                experience: labor.experience,
                availability_status: labor.availability_status,
                type: 'Labor'
            }
        });
    } catch (error) {
        console.error('❌ Error in Labor Google sign-in:', error);
        res.status(500).json({ 
            error: 'Internal server error',
            details: error.message
        });
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

// Chat Room Schema
const chatRoomSchema = new mongoose.Schema({
    participants: [{
        type: mongoose.Schema.Types.ObjectId,
        refPath: 'participantTypes'
    }],
    participantTypes: [{
        type: String,
        enum: ['User', 'Labor']
    }],
    lastMessage: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Message'
    },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

const ChatRoom = mongoose.model('ChatRoom', chatRoomSchema);

// Message Schema
const messageSchema = new mongoose.Schema({
    chatRoom: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'ChatRoom',
        required: true
    },
    sender: {
        type: mongoose.Schema.Types.ObjectId,
        refPath: 'senderType',
        required: true
    },
    senderType: {
        type: String,
        enum: ['User', 'Labor'],
        required: true
    },
    receiver: {
        type: mongoose.Schema.Types.ObjectId,
        refPath: 'receiverType',
        required: true
    },
    receiverType: {
        type: String,
        enum: ['User', 'Labor'],
        required: true
    },
    content: {
        type: String,
        required: true
    },
    readBy: [{
        type: mongoose.Schema.Types.ObjectId,
        refPath: 'readByTypes'
    }],
    readByTypes: [{
        type: String,
        enum: ['User', 'Labor']
    }],
    createdAt: { type: Date, default: Date.now }
});

const Message = mongoose.model('Message', messageSchema);

// Socket.IO connection handling
io.on('connection', (socket) => {
    console.log('New client connected');

    socket.on('join_room', (roomId) => {
        socket.join(roomId);
        console.log(`User joined room: ${roomId}`);
    });

    socket.on('leave_room', (roomId) => {
        socket.leave(roomId);
        console.log(`User left room: ${roomId}`);
    });

    socket.on('disconnect', () => {
        console.log('Client disconnected');
    });
});

// Send message
app.post('/api/chat/message', authenticateToken, async (req, res) => {
    try {
        const { chatRoomId, content, receiverId, receiverType } = req.body;
        const senderId = req.user.id;
        const senderType = req.user.type || 'User';
        
        console.log('📥 Incoming message request:', {
            chatRoomId,
            content,
            senderId,
            senderType,
            receiverId,
            receiverType
        });

        if (!chatRoomId || !content || !receiverId || !receiverType) {
            console.error('❌ Missing required fields:', { 
                chatRoomId, 
                content, 
                receiverId, 
                receiverType 
            });
            return res.status(400).json({ 
                error: 'Missing required fields',
                details: 'chatRoomId, content, receiverId, and receiverType are required'
            });
        }

        // Verify chat room exists and user is a participant
        const chatRoom = await ChatRoom.findById(chatRoomId);
        if (!chatRoom) {
            console.error('❌ Chat room not found:', chatRoomId);
            return res.status(404).json({ error: 'Chat room not found' });
        }

        if (!chatRoom.participants.includes(senderId) || !chatRoom.participants.includes(receiverId)) {
            console.error('❌ User not authorized in chat room:', { senderId, receiverId, chatRoomId });
            return res.status(403).json({ error: 'Not authorized in this chat room' });
        }

        // Create new message
        const message = new Message({
            chatRoom: chatRoomId,
            sender: senderId,
            senderType: senderType,
            receiver: receiverId,
            receiverType: receiverType,
            content,
            readBy: [senderId],
            readByTypes: [senderType]
        });

        console.log('📝 Creating new message:', {
            chatRoomId,
            senderId,
            senderType,
            receiverId,
            receiverType,
            contentLength: content.length
        });

        await message.save();

        // Update chat room's last message
        await ChatRoom.findByIdAndUpdate(chatRoomId, {
            lastMessage: message._id,
            updatedAt: new Date()
        });

        // Manually populate sender and receiver details
        const senderModel = senderType === 'User' ? User : Labor;
        const receiverModel = receiverType === 'User' ? User : Labor;

        const [sender, receiver] = await Promise.all([
            senderModel.findById(senderId).select('fullName name profilePicture'),
            receiverModel.findById(receiverId).select('fullName name profilePicture')
        ]);

        // Handle cases where sender or receiver is not found
        if (!sender || !receiver) {
            console.error('❌ Participant not found:', { 
                senderFound: !!sender, 
                receiverFound: !!receiver 
            });
            return res.status(404).json({ 
                error: 'Participant not found',
                details: 'One or more participants could not be found'
            });
        }

        // Construct the response
        const response = {
            _id: message._id,
            content: message.content,
            sender: {
                _id: senderId,
                type: senderType,
                name: sender.name || sender.fullName,
                profilePicture: sender.profilePicture
            },
            receiver: {
                _id: receiverId,
                type: receiverType,
                name: receiver.name || receiver.fullName,
                profilePicture: receiver.profilePicture
            },
            senderType: message.senderType,
            receiverType: message.receiverType,
            createdAt: message.createdAt
        };

        // Emit message to all users in the chat room
        io.to(chatRoomId).emit('new_message', response);

        console.log('✅ Message sent successfully:', {
            messageId: message._id,
            chatRoomId,
            senderId,
            receiverId
        });

        res.status(201).json({ 
            message: response,
            status: 'success'
        });
    } catch (error) {
        console.error('❌ Error sending message:', error);
        res.status(500).json({ 
            error: 'Internal server error',
            details: error.message
        });
    }
});

// Get messages for a chat room
app.get('/api/chat/messages/:chatRoomId', authenticateToken, async (req, res) => {
    try {
        const { chatRoomId } = req.params;
        const userId = req.user.id;
        const userType = req.user.type || 'User';

        console.log('📥 Fetching messages for chat room:', {
            chatRoomId,
            userId,
            userType
        });

        // First verify chat room exists
        const chatRoom = await ChatRoom.findById(chatRoomId)
            .populate('lastMessage');
            
        if (!chatRoom) {
            console.error('❌ Chat room not found:', chatRoomId);
            return res.status(404).json({ error: 'Chat room not found' });
        }

        // Verify user is a participant
        if (!chatRoom.participants.includes(userId)) {
            console.error('❌ User not authorized in chat room:', { userId, chatRoomId });
            return res.status(403).json({ error: 'Not authorized in this chat room' });
        }

        // Find all messages for this chat room
        const messages = await Message.find({ chatRoom: chatRoomId })
            .sort({ createdAt: 1 });

        console.log('📝 Found messages:', messages.length);

        // Manually populate sender and receiver details for each message
        const populatedMessages = await Promise.all(
            messages.map(async (message) => {
                const senderModel = message.senderType === 'User' ? User : Labor;
                const receiverModel = message.receiverType === 'User' ? User : Labor;

                const [sender, receiver] = await Promise.all([
                    senderModel.findById(message.sender).select('fullName name profilePicture mobile_number phoneNumber skill location pricePerDay category availability_status'),
                    receiverModel.findById(message.receiver).select('fullName name profilePicture mobile_number phoneNumber skill location pricePerDay category availability_status')
                ]);

                // Skip messages where participants are not found
                if (!sender || !receiver) {
                    console.warn('⚠️ Skipping message due to missing participant:', {
                        messageId: message._id,
                        senderFound: !!sender,
                        receiverFound: !!receiver
                    });
                    return null;
                }

                // Construct sender details
                const senderDetails = {
                    _id: message.sender,
                    type: message.senderType,
                    name: sender.name || sender.fullName,
                    profilePicture: sender.profilePicture
                };

                // Add type-specific fields for sender
                if (message.senderType === 'Labor') {
                    Object.assign(senderDetails, {
                        skill: sender.skill,
                        location: sender.location,
                        pricePerDay: sender.pricePerDay,
                        category: sender.category,
                        availability_status: sender.availability_status,
                        mobile_number: sender.mobile_number
                    });
                } else {
                    Object.assign(senderDetails, {
                        phoneNumber: sender.phoneNumber
                    });
                }

                // Construct receiver details
                const receiverDetails = {
                    _id: message.receiver,
                    type: message.receiverType,
                    name: receiver.name || receiver.fullName,
                    profilePicture: receiver.profilePicture
                };

                // Add type-specific fields for receiver
                if (message.receiverType === 'Labor') {
                    Object.assign(receiverDetails, {
                        skill: receiver.skill,
                        location: receiver.location,
                        pricePerDay: receiver.pricePerDay,
                        category: receiver.category,
                        availability_status: receiver.availability_status,
                        mobile_number: receiver.mobile_number
                    });
                } else {
                    Object.assign(receiverDetails, {
                        phoneNumber: receiver.phoneNumber
                    });
                }

                return {
                    _id: message._id,
                    content: message.content,
                    sender: senderDetails,
                    receiver: receiverDetails,
                    senderType: message.senderType,
                    receiverType: message.receiverType,
                    readBy: message.readBy || [],
                    readByTypes: message.readByTypes || [],
                    createdAt: message.createdAt
                };
            })
        );

        // Filter out null messages (where participants were not found)
        const validMessages = populatedMessages.filter(msg => msg !== null);

        console.log('✅ Retrieved messages:', {
            chatRoomId,
            messageCount: validMessages.length,
            hasLastMessage: !!chatRoom.lastMessage
        });

        res.status(200).json({ 
            messages: validMessages,
            lastMessage: chatRoom.lastMessage,
            status: 'success'
        });
    } catch (error) {
        console.error('❌ Error fetching messages:', error);
        res.status(500).json({ 
            error: 'Internal server error',
            details: error.message
        });
    }
});

// Create or get chat room
app.post('/api/chat/room', authenticateToken, async (req, res) => {
    try {
        const { participantId, participantType } = req.body;
        const currentUserId = req.user.id;
        const currentUserType = req.user.type || 'User';

        console.log('📥 Creating/getting chat room:', {
            currentUserId,
            currentUserType,
            participantId,
            participantType
        });

        if (!participantId || !participantType) {
            console.error('❌ Missing required fields:', { participantId, participantType });
            return res.status(400).json({ 
                error: 'Missing required fields',
                details: 'participantId and participantType are required'
            });
        }

        // Find existing chat room with both participants, regardless of who created it
        let chatRoom = await ChatRoom.findOne({
            $and: [
                { participants: { $all: [currentUserId, participantId] } },
                { participantTypes: { $all: [currentUserType, participantType] } }
            ]
        });

        console.log('🔍 Searching for existing chat room:', {
            participants: [currentUserId, participantId],
            types: [currentUserType, participantType],
            found: !!chatRoom
        });

        if (!chatRoom) {
            console.log('📝 Creating new chat room');
            // Create new chat room with both participants and their types
            chatRoom = new ChatRoom({
                participants: [currentUserId, participantId],
                participantTypes: [currentUserType, participantType]
            });
            await chatRoom.save();
            console.log('✅ New chat room created:', chatRoom._id);
        } else {
            console.log('✅ Found existing chat room:', chatRoom._id);
        }

        // First populate the chat room without dynamic model references
        const populatedChatRoom = await ChatRoom.findById(chatRoom._id)
            .populate('lastMessage');

        // Then manually populate participant details
        const participants = await Promise.all(
            chatRoom.participants.map(async (participantId, index) => {
                const type = chatRoom.participantTypes[index];
                const model = type === 'User' ? User : Labor;
                const participant = await model.findById(participantId)
                    .select('fullName name profilePicture mobile_number phoneNumber skill location pricePerDay category availability_status');
                
                if (!participant) {
                    console.warn('⚠️ Participant not found:', { participantId, type });
                    return {
                        _id: participantId,
                        type: type,
                        name: type === 'User' ? 'Unknown User' : 'Unknown Labor',
                        profilePicture: 'https://via.placeholder.com/150'
                    };
                }

                // Construct participant details based on type
                const participantDetails = {
                    _id: participantId,
                    type: type,
                    name: participant.name || participant.fullName || 'Unknown',
                    profilePicture: participant.profilePicture || 'https://via.placeholder.com/150'
                };

                // Add type-specific fields
                if (type === 'Labor') {
                    Object.assign(participantDetails, {
                        skill: participant.skill || 'Not specified',
                        location: participant.location || 'Not specified',
                        pricePerDay: participant.pricePerDay || 0,
                        category: participant.category || 'General',
                        availability_status: participant.availability_status || 'Available',
                        mobile_number: participant.mobile_number || 'Not specified'
                    });
                } else {
                    Object.assign(participantDetails, {
                        phoneNumber: participant.phoneNumber || 'Not specified'
                    });
                }

                return participantDetails;
            })
        );

        // Get the other participant (not the current user)
        const otherParticipant = participants.find(p => p._id !== currentUserId);

        // Construct the final response
        const response = {
            _id: populatedChatRoom._id,
            participants: participants,
            otherParticipant: otherParticipant,
            lastMessage: populatedChatRoom.lastMessage,
            createdAt: populatedChatRoom.createdAt,
            updatedAt: populatedChatRoom.updatedAt
        };

        console.log('✅ Chat room details:', {
            chatRoomId: chatRoom._id,
            participants: participants.map(p => ({ id: p._id, type: p.type })),
            hasLastMessage: !!populatedChatRoom.lastMessage
        });

        res.status(200).json({ 
            chatRoom: response,
            status: 'success'
        });
    } catch (error) {
        console.error('❌ Error creating chat room:', error);
        res.status(500).json({ 
            error: 'Internal server error',
            details: error.message
        });
    }
});

// Get chat rooms for a user/labor
app.get('/api/chat/rooms', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const userType = req.user.type || 'User';

        console.log('📥 Fetching chat rooms for:', { userId, userType });

        // Find chat rooms where the user/labor is a participant
        const chatRooms = await ChatRoom.find({
            participants: userId,
            participantTypes: userType
        })
        .populate('lastMessage')
        .sort({ updatedAt: -1 });

        // Manually populate participant details for each chat room
        const populatedChatRooms = await Promise.all(
            chatRooms.map(async (chatRoom) => {
                const participants = await Promise.all(
                    chatRoom.participants.map(async (participantId, index) => {
                        const type = chatRoom.participantTypes[index];
                        const model = type === 'User' ? User : Labor;
                        const participant = await model.findById(participantId)
                            .select('fullName name profilePicture mobile_number phoneNumber skill location pricePerDay category availability_status');
                        
                        if (!participant) {
                            console.warn('⚠️ Participant not found:', { participantId, type });
                            return null;
                        }

                        // Construct participant details based on type
                        const participantDetails = {
                            _id: participantId,
                            type: type,
                            name: participant.name || participant.fullName,
                            profilePicture: participant.profilePicture
                        };

                        // Add type-specific fields
                        if (type === 'Labor') {
                            Object.assign(participantDetails, {
                                skill: participant.skill,
                                location: participant.location,
                                pricePerDay: participant.pricePerDay,
                                category: participant.category,
                                availability_status: participant.availability_status,
                                mobile_number: participant.mobile_number
                            });
                        } else {
                            Object.assign(participantDetails, {
                                phoneNumber: participant.phoneNumber
                            });
                        }

                        return participantDetails;
                    })
                );

                // Filter out null participants
                const validParticipants = participants.filter(p => p !== null);

                // Get the other participant (not the current user)
                const otherParticipant = validParticipants.find(p => p._id !== userId);

                return {
                    _id: chatRoom._id,
                    participants: validParticipants,
                    otherParticipant: otherParticipant, // Add the other participant for easy access
                    lastMessage: chatRoom.lastMessage,
                    createdAt: chatRoom.createdAt,
                    updatedAt: chatRoom.updatedAt
                };
            })
        );

        console.log('✅ Found chat rooms:', populatedChatRooms.length);

        res.status(200).json({ 
            chatRooms: populatedChatRooms,
            status: 'success'
        });
    } catch (error) {
        console.error('❌ Error fetching chat rooms:', error);
        res.status(500).json({ 
            error: 'Internal server error',
            details: error.message
        });
    }
});

// Mark messages as read
app.put('/api/chat/messages/read', authenticateToken, async (req, res) => {
    try {
        const { chatRoomId } = req.body;
        const userId = req.user.id;

        await Message.updateMany(
            {
                chatRoom: chatRoomId,
                readBy: { $ne: userId }
            },
            {
                $addToSet: { readBy: userId }
            }
        );

        res.status(200).json({ message: 'Messages marked as read' });
    } catch (error) {
        console.error('Error marking messages as read:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get all bookings for a specific labor
app.get('/api/bookings/labor/:laborId/all', authenticateToken, async (req, res) => {
    try {
        const { laborId } = req.params;
        console.log('📥 Fetching all bookings for labor:', laborId);

        // Validate laborId
        if (!laborId) {
            console.error('❌ No labor ID provided');
            return res.status(400).json({ 
                error: 'Labor ID is required',
                details: 'Please provide a valid labor ID'
            });
        }

        // Find all bookings for this labor
        const bookings = await Booking.find({ labor_id: laborId })
            .populate('user_id', 'fullName phoneNumber')
            .sort({ createdAt: -1 }); // Sort by newest first

        console.log('✅ Found bookings:', bookings.length);

        res.status(200).json(bookings);
    } catch (error) {
        console.error('❌ Error fetching labor bookings:', error);
        res.status(500).json({ 
            error: 'Internal server error',
            details: error.message
        });
    }
});

// Start the server
server.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});