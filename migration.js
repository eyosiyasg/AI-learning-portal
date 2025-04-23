

const uri = "mongodb+srv://johnDoe:12345@studyappcluster.0ludj.mongodb.net/?retryWrites=true&w=majority&appName=studyAppCluster";
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
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


// Create User Model
const User = mongoose.model('User', userSchema); //the path to your User model

mongoose.connect(uri, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

async function hashOldPasswords() {
  try {
    // Fetch users whose passwords are **not hashed** (assuming they're stored as plain text)
    const users = await User.find();

    for (let user of users) {
      if (!user.password.startsWith("$2b$")) { // Check if password is already hashed
        const hashedPassword = await bcrypt.hash(user.password, 10);
        user.password = hashedPassword;
        await user.save();
        console.log(`Updated password for user: ${user.username}`);
      }
    }

    console.log("All old passwords have been hashed!");
    mongoose.connection.close();
  } catch (error) {
    console.error("Error updating passwords:", error);
    mongoose.connection.close();
  }
}

hashOldPasswords();
