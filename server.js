const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const app = express();
const jwt = require("jsonwebtoken");
const SECRET_KEY = process.env.SECRET_KEY;
const bcrypt = require("bcryptjs");
const port = process.env.PORT || 5000
const BASE_URL = window.location.hostname === "localhost" ? "http://localhost:5000" : "https://your-app-name.onrender.com";
require('dotenv').config()
// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'))

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// Define User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  securityQuestion: { type: String, required: true },
  securityAnswer: { type: String, required: true },
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

userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});
// Create User Model
const User = mongoose.model('User', userSchema);

// 🟢 Register a new user
app.post('/register', async (req, res) => {
  console.log("Started registration of the user");
  const { username, email, password, securityQuestion, securityAnswer } = req.body;
  
  try {
    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      return res.status(400).json({ message: 'Username or email already exists' });
    }

    const newUser = new User({
      username,
      email,
      password,
      securityQuestion,
      securityAnswer,
      friendRequestsSent: [],
      friendRequestsReceived: [],
      friends: []
    });

    await newUser.save();
    console.log("User registered:", newUser);
    res.status(201).json({ message: 'User registered successfully!' });
  } catch (err) {
    console.error("Registration error:", err);
    res.status(500).json({ error: err.message });
  }
});

// 🟢 Login a user

app.post('/login', async (req, res) => {
  console.log("Login attempt");
  // const { username, password } = req.body;
  
  try {
    const { username, password } = req.body;
   const user = await User.findOne({ username });

  if (!user) return res.status(400).json({ error: "User not found" });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(401).json({ error: "Invalid credentials" });

  // Generate JWT Token
  const token = jwt.sign({ username: user.username, id: user._id }, SECRET_KEY, { expiresIn: "1h" });

    res.status(200).json({ message: 'Login successful!',token})
    // res.status(200).json({ message: 'Login successful!', userData: {
    //   username: user.username,
    //   friends: user.friends,
    //   friendRequestsSent: user.friendRequestsSent,
    //   friendRequestsReceived: user.friendRequestsReceived
    // }});

  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: err.message });
  }
});


function verifyToken(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) return res.status(401).json({ error: "Unauthorized" });
console.log(token)
console.log(SECRET_KEY)
  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) return res.status(403).json({ error: "Invalid token" });
    req.user = decoded;
    next();
  });
}

// Protected Route: Get User Data
app.get("/get-user", verifyToken, async (req, res) => {
  const user = await User.findById(req.user.id).select("-password");
  res.json(user);
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
        'Authorization': `Bearer ynNPtE804WLyawrSGF9hAITc4B7cMduS` // Use environment variable
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



// Start the server
app.listen(5000, () => {
    console.log(`Server running on port ${5000}`);
});