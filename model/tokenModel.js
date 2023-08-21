import mongoose from "mongoose";

const tokenSchema = mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    required: true,
    ref: "user",
  },
  vToken: {
    type: String,
    default: "",
  }, //verification token
  rToken: {
    type: String,
    default: "",
  }, //reset token
  lToken: {
    type: String,
    default: "",
  }, //login token

  createdAt: {
    type: Date,
    required: true,
  },
  expiresAt: {
    type: Date,
    required: true,
  },
});

const Token = mongoose.model("Token", tokenSchema);

export default Token;
