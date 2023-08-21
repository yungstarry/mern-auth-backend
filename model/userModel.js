// models/User.model.js
import mongoose from "mongoose";
import validator from "validator";
import bcrypt from "bcryptjs";

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      minLength: [2, "First name must be at least 2 characters long"],
      maxLength: [12, "First name must not be more than 12 characters long"],
    },

    email: {
      type: String,
      required: true,
      unique: [true, "Email address must be unique "],
      validate: validator.isEmail,
    },
    password: {
      type: String,
      required: true,
    },

    photo: {
      type: String,
      required: [true, "Please add a photo"],
      default: "https://i.ibb.co/4pDNDk1/avatar.png",
    },
    phone: {
      type: String,
      default: "+234",
    },
    bio: {
      type: String,
      maxLength: [250, "Bio must not be more than 250 characters long"],
      default: "bio",
    },
    role: {
      type: String,
      required: true,
      default: "subscriber",
      //   enum: ["admins", "author", "suspended", "u"],
    },
    isVerified: {
      type: Boolean,
      default: false,
    },
    userAgent: {
      type: Array,
      required: true,
      default: [],
    },
  },
  { timestamps: true, minimize: false }
);

//Encrpty password before saving to DB
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) {
    return next();
  }

  // hAsh Password
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(this.password, salt);
  this.password = hashedPassword;
  next();
});

const User = mongoose.model("User", userSchema);

export default User;
