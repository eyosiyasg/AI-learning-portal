import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import path from "path";
import { fileURLToPath } from "url";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import nodemailer from 'nodemailer'
import { v4 as uuidv4 } from 'uuid'

dotenv.config(); // load .env file

const app = express();
const __dirname = path.dirname(fileURLToPath(import.meta.url));

app.use(cors());
app.use(express.json());

// Get values from .env
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET || "supersecret";
const PORT = process.env.PORT || 3000;

// MongoDB connection
mongoose.connect(MONGO_URI)
  .then(() => console.log("✅ Connected to MongoDB Atlas"))
  .catch(err => console.error("❌ MongoDB connection error:", err));

// User schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  friendRequestsSent: { type: [Object], default: [] },
  friendRequestsReceived: { type: [Object], default: [] },
  friends: [{
    name: String,
    chatHistory: {
      sent: [{ type: { type: String }, content:  { type: String }, date: {type: String} }],  // ✅ Corrected
      received: [{ type: { type: String }, content:  { type: String }, date: {type: String} }] 
    }
  }]
});

// Hash before saving
userSchema.pre("save", async function(next) {
  if (!this.isModified("password")) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

const User = mongoose.model("User", userSchema);

// Register
const users = [];
const verificationCodes = new Map();

// Configure email transporter
const transporter = nodemailer.createTransport({
  service: 'gmail', // or your email service
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Password validation middleware
const validatePassword = (password) => {
  const minLength = password.length >= 8;
  const hasUpperCase = /[A-Z]/.test(password);
  const hasLowerCase = /[a-z]/.test(password);
  const hasNumber = /\d/.test(password);
  const hasSpecialChar = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password);
  
  return minLength && hasUpperCase && hasLowerCase && hasNumber && hasSpecialChar;
};

// Register endpoint
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Check if user already exists
    if (users.find(u => u.username === username)) {
      return res.status(400).json({ message: 'Username already exists' });
    }
    
    if (users.find(u => u.email === email)) {
      return res.status(400).json({ message: 'Email already registered' });
    }

    // Validate password
    if (!validatePassword(password)) {
      return res.status(400).json({ 
        message: 'Password must be at least 8 characters long and contain uppercase, lowercase, number, and special character' 
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Create user (but don't mark as verified yet)
    const user = {
      id: uuidv4(),
      username,
      email,
      password: hashedPassword,
      verified: false,
      createdAt: new Date()
    };
    
    users.push(user);

    // Generate verification code
    const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
    verificationCodes.set(email, {
      code: verificationCode,
      expires: Date.now() + 300000 // 5 minutes
    });

    // Send verification email
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Verify Your Email Address',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #8a2be2;">Email Verification</h2>
          <p>Hello ${username},</p>
          <p>Thank you for registering. Please use the following verification code to complete your registration:</p>
          <div style="text-align: center; margin: 20px 0;">
            <span style="font-size: 24px; font-weight: bold; letter-spacing: 5px; color: #8a2be2;">${verificationCode}</span>
          </div>
          <p>This code will expire in 5 minutes.</p>
          <p>If you didn't create an account, please ignore this email.</p>
        </div>
      `
    };

    await transporter.sendMail(mailOptions);

    res.json({ 
      message: 'Registration successful. Please check your email for verification code.',
      userId: user.id
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Verify email endpoint
app.post('/api/verify-email', async (req, res) => {
  try {
    const { email, code } = req.body;
    
    // Find user
    const user = users.find(u => u.email === email);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    // Check if already verified
    if (user.verified) {
      return res.status(400).json({ message: 'Email already verified' });
    }
    
    // Check verification code
    const storedCode = verificationCodes.get(email);
    if (!storedCode) {
      return res.status(400).json({ message: 'No verification code found for this email' });
    }
    
    if (Date.now() > storedCode.expires) {
      verificationCodes.delete(email);
      return res.status(400).json({ message: 'Verification code has expired' });
    }
    
    if (storedCode.code !== code) {
      return res.status(400).json({ message: 'Invalid verification code' });
    }
    
    // Mark user as verified
    user.verified = true;
    verificationCodes.delete(email);
    
    res.json({ message: 'Email verified successfully' });
  } catch (error) {
    console.error('Verification error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Resend verification code endpoint
app.post('/api/resend-verification', async (req, res) => {
  try {
    const { email } = req.body;
    
    // Find user
    const user = users.find(u => u.email === email);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    if (user.verified) {
      return res.status(400).json({ message: 'Email already verified' });
    }
    
    // Generate new verification code
    const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
    verificationCodes.set(email, {
      code: verificationCode,
      expires: Date.now() + 300000 // 5 minutes
    });
    
    // Send verification email
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Your New Verification Code',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #8a2be2;">New Verification Code</h2>
          <p>Hello ${user.username},</p>
          <p>Here is your new verification code:</p>
          <div style="text-align: center; margin: 20px 0;">
            <span style="font-size: 24px; font-weight: bold; letter-spacing: 5px; color: #8a2be2;">${verificationCode}</span>
          </div>
          <p>This code will expire in 5 minutes.</p>
        </div>
      `
    };

    await transporter.sendMail(mailOptions);
    
    res.json({ message: 'New verification code sent' });
  } catch (error) {
    console.error('Resend verification error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Login endpoint (updated to check verification status)
app.post('/api/login', async (req, res) => {
  try {
    const { login, password } = req.body;
    
    // Find user by username or email
    const user = users.find(u => u.username === login || u.email === login);
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }
    
    // Check password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }
    
    // Check if email is verified
    if (!user.verified) {
      return res.status(403).json({ 
        message: 'Please verify your email before logging in',
        needsVerification: true,
        email: user.email
      });
    }
    
    // Generate JWT token
    const token = jwt.sign(
      { userId: user.id, username: user.username, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    // localStorage.setItem("token", token)
    
    res.json({ token, username: user.username, email: user.email, id:user.id });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});
// Protected route
// app.get("/api/get-user", async (req, res) => {
//   try {
//     const auth = req.headers.authorization;
//     if (!auth) return res.status(401).json({ message: "No token" });

//     const token = auth.split(" ")[1];
//     const decoded = jwt.verify(token, JWT_SECRET);

//     const user = await User.findById(decoded.id).select("-password");
//     if (!user) return res.status(404).json({ message: "User not found" });

//     res.json(user);
//   } catch {
//     res.status(401).json({ message: "Invalid token" });
//   }
// });

// Add this endpoint to your server.js
app.get('/api/get-user', (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ message: 'No token provided' });
    }
    
    const token = authHeader.substring(7); // Remove "Bearer " prefix
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Find user by ID from the token
    const user = users.find(u => u.id === decoded.userId);
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    // Return user data without sensitive information
    res.json({ 
      id: user.id,
      username: user.username, 
      email: user.email,
      verified: user.verified
    });
  } catch (error) {
    console.error('Get user error:', error);
    
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ message: 'Token expired' });
    }
    
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ message: 'Invalid token' });
    }
    
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Endpoint to get user data by username (including friends, friend requests, etc.)
app.get('/user/:username', async (req, res) => {
  const { username } = req.params;  // Get the username from the URL params
  try {
    const user = await User.findOne({ username: username });
    console.log(user)
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    // Return user data (you can adjust what to return here based on your needs)
    res.json({
      username: user.username,
      friends: user.friends,
      friendRequestsSent: user.friendRequestsSent,
      friendRequestsReceived: user.friendRequestsReceived
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


app.get('/search', async (req, res) => {
  const { username } = req.query;
  try {
    const users = await User.find({ username: { $regex: username, $options: 'i' } });
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Endpoint to send a friend request
app.post('/send-friend-request', async (req, res) => {
  const { requester, recipient } = req.body;
  console.log('0')
  try {
    const recipientUser = await User.findOne({ username: recipient });
    const requesterUser = await User.findOne({ username: requester });

    if (!recipientUser) {
      return res.status(404).json({ error: 'User not found' });
    }

    let checkForRequest = requesterUser.friendRequestsSent.find(user => user.username===recipient)

    if(checkForRequest){
      console.log('friend already exist')
     return res.json({ message: 'friend request already sent to the user' });}
    // Add the request to the recipient's friendRequestsReceived


    try {
    recipientUser.friendRequestsReceived.push({ username: requester, status: 'in-progress' });
    await recipientUser.save();
    } catch(err) {console.log(err)}

    // Add the request to the requester's friendRequestsSent
    requesterUser.friendRequestsSent.push({ username: recipient, status: 'in-progress' });
    await requesterUser.save();


    res.json({ message: 'Friend request sent' });
  } catch (err) {
    console.log("error occured broski")
    res.status(500).json({ error: err.message });
  }
});

app.get("/get-friend-requests", async (req, res) => {
  const { username } = req.query;

  try {
    const user = await User.findOne({ username });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.status(200).json({ friendRequestsReceived: user.friendRequestsReceived });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/handle-friend-request", async (req, res) => {
  const { username, requesterUsername, action } = req.body;

  try {
    const user = await User.findOne({ username });
    const requesterUser = await User.findOne({ username: requesterUsername });
    console.log(user.friendRequestsReceived)

  const requester = user.friendRequestsReceived.find(user => user.username===requesterUsername)
  console.log(requester)
    if (!user || !requesterUser) {
      return res.status(404).json({ error: "User not found" });
    }

    // Ensure the requester is in the received requests
    if (!user.friendRequestsReceived.includes(requester)) {
      return res.status(400).json({ error: "No pending request from this user." });
    }

    if (action === "accept") {
      // Add each other as friends
      user.friends.push({name: requesterUsername, chatHistory: { sent: [], received: [] } });
      requesterUser.friends.push({name: username, chatHistory: { sent: [], received: [] } });

      // Remove from requests lists
      user.friendRequestsReceived = user.friendRequestsReceived.filter((r) => r.username !== requesterUsername);
      requesterUser.friendRequestsSent = requesterUser.friendRequestsSent.filter((r) => r.username !== username);
    } else if (action === "reject") {
      // Just remove the request
      user.friendRequestsReceived = user.friendRequestsReceived.filter((r) => r.username !== requesterUsername);
      requesterUser.friendRequestsSent = requesterUser.friendRequestsSent.filter((r) => r.username !== username);
    }

    await user.save();
    await requesterUser.save();

    res.status(200).json({ message: `Friend request ${action}ed successfully.` });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post('/unfollow', async (req, res) => {
    const { requester, recipient } = req.body;

    try {
        if (!requester || !recipient) {
            return res.status(400).json({ message: "Missing requester or recipient." });
        }

        // Find both users
        const requesterUser = await User.findOne({ username: requester });
        const recipientUser = await User.findOne({ username: recipient });

        if (!requesterUser || !recipientUser) {
            return res.status(404).json({ message: "User not found." });
        }

        // Remove each other from friends list
        requesterUser.friends = requesterUser.friends.filter(friend => friend.name !== recipient);
        recipientUser.friends = recipientUser.friends.filter(friend => friend.name !== requester);

        // Save changes
        await requesterUser.save();
        await recipientUser.save();

        res.json({ message: `You have unfollowed ${recipient}.` });

    } catch (error) {
        console.error("Error unfollowing user:", error);
        res.status(500).json({ message: "Server error. Please try again." });
    }
});

app.get('/friend-suggestions/:username', async (req, res) => {
    const { username } = req.params;

    try {
        const user = await User.findOne({ username });

        if (!user) {
            return res.status(404).json({ message: "User not found." });
        }

        let suggestedFriends = new Set();

        // Loop through each friend of the user
        for (const friend of user.friends) {
            const friendUser = await User.findOne({ username: friend.name });

            if (friendUser) {
                // Add their friends to suggestions, but exclude the user and their existing friends
                friendUser.friends.forEach(potentialFriend => {
                      if (
                        potentialFriend.name !== username &&
                        !user.friends.some(existingFriend => existingFriend.name === potentialFriend.name)
                           ){
            suggestedFriends.add(potentialFriend.name);
          }
                });
            }
        }

        res.json({ suggestions: Array.from(suggestedFriends) });

    } catch (error) {
        console.error("Error fetching friend suggestions:", error);
        res.status(500).json({ message: "Server error. Please try again." });
    }
});


app.post('/send-message', async (req, res) => {
  console.log("sending started!")
    const { sender, receiver, type, content, date } = req.body;
    
    try {
        const senderUser = await User.findOne({ username: sender });
        const receiverUser = await User.findOne({ username: receiver });
        
        if (!senderUser || !receiverUser) {
            return res.status(404).json({ message: 'User not found' });
        }
        
        // Find or create chat history for sender
        let senderFriend = senderUser.friends.find(f => f.name === receiver);
        if (!senderFriend) {
            senderFriend = { name: receiver, chatHistory: { sent: [], received: [] } };
            senderUser.friends.push(senderFriend);
        }
        senderFriend.chatHistory.sent.push({ type, content, date});

        // Find or create chat history for receiver
        let receiverFriend = receiverUser.friends.find(f => f.name === sender);
        if (!receiverFriend) {
            receiverFriend = { name: sender, chatHistory: { sent: [], received: [] } };
            receiverUser.friends.push(receiverFriend);
        }
        receiverFriend.chatHistory.received.push({ type, content, date });
        
        await senderUser.save();
        await receiverUser.save();

        res.json({ message: 'Message sent successfully' });
    } catch (error) {
        console.error('Error sending message:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/chat-users', async (req, res) => {
  const { username, friend } = req.query;

  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(404).json({ error: "User not found" });

    // Find the specific friend in the user's friends list
    const friendData = user.friends.find(f => f.name === friend);
    if (!friendData) return res.status(404).json({ error: "Friend not found" });

    res.json({ username, friend, chatHistory: friendData.chatHistory });
  } catch (error) {
    console.error("Error fetching chat users:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});




// voice chat section



app.post('/proxy/mistral', async (req, res) => {
  try {
    const response = await fetch('https://api.mistral.ai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer FxveCwb3VQPxv9mZ6tbc4GQeyTWQSp2R` // Use environment variable
      },
      body: JSON.stringify(req.body)
    });

    if (!response.ok) {
      throw new Error(`Mistral API error: ${response.statusText}`);
    }

    const data = await response.json();
    res.json(data);
  } catch (error) {
    console.error("Proxy Error:", error);
    res.status(500).json({ error: error.message });
  }
});


// Serve frontend
app.use(express.static(path.join(__dirname, "public")));
app.get(/^(?!\/api).*/, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => console.log(`🚀 Server running at http://localhost:${PORT}`));
