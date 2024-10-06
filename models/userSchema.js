import mongoose from "mongoose";
import bcrypt from "bcryptjs"; // Use bcryptjs instead of bcrypt
// import jwt from "jsonwebtoken";
import crypto from "crypto";
import jwt from 'jsonwebtoken'

const userSchema = new mongoose.Schema({
  fullName: {
    type: String,
    required: [true, "Name Required!"],
  },
  email: {
    type: String,
    required: [true, "Email Required!"],
  },
  phone: {
    type: String,
    required: [true, "Phone Required!"],
  },
  aboutMe: {
    type: String,
    required: [true, "About Me Section Is Required!"],
  },
  password: {
    type: String,
    required: [true, "Password Required!"],
    minLength: [8, "Password Must Contain At Least 8 Characters!"],
    select: false,
  },
  avatar: {
    public_id: {
      type: String,
      required: true,
    },
    url: {
      type: String,
      required: true,
    },
  },
  resume: {
    public_id: {
      type: String,
      required: true,
    },
    url: {
      type: String,
      required: true,
    },
  },
  portfolioURL: {
    type: String,
    required: [true, "Portfolio URL Required!"],
  },
  githubURL: {
    type: String,
  },
  instagramURL: {
    type: String,
  },
  twitterURL: {
    type: String,
  },
  linkedInURL: {
    type: String,
  },
  facebookURL: {
    type: String,
  },
  resetPasswordToken: String,
  resetPasswordExpire: Date,
});

// Pre-save hook to hash password
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) {
    return next(); // Ensure to return next()
  }

  // Hashing password using bcryptjs
  this.password = await bcrypt.hash(this.password, 10);
  next(); // Call next() after hashing
});

// Method to compare entered password with hashed password
userSchema.methods.comparePassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

// Method to generate JSON Web Token
userSchema.methods.generateJsonWebToken = function () {
  return jwt.sign({ id: this._id }, process.env.JWT_SECRET_KEY, {
    expiresIn: process.env.JWT_EXPIRES,
  });
};

// Generating Reset Password Token
userSchema.methods.getResetPasswordToken = function () {
  // Generating Token
  const resetToken = crypto.randomBytes(20).toString("hex");

  // Hashing and Adding Reset Password Token To UserSchema
  this.resetPasswordToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");

  // Setting Reset Password Token Expiry Time
  this.resetPasswordExpire = Date.now() + 15 * 60 * 1000;

  return resetToken; // Return the plain reset token
};

export const User = mongoose.model("User", userSchema);
