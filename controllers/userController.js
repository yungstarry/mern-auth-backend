import asyncHandler from "express-async-handler";
import User from "../model/userModel.js";
import bcrypt from "bcryptjs";
import { generateToken, hashToken } from "../utils/index.js";
import parser from "ua-parser-js";
import jwt from "jsonwebtoken";
import sendEmail from "../utils/sendEmail.js";
import Token from "../model/tokenModel.js";
import crypto from "crypto";
import Cryptr from "cryptr";
import dotenv from "dotenv";
import { OAuth2Client } from "google-auth-library";

dotenv.config();

const cryptr = new Cryptr(process.env.CRYPTR_KEY);
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

const registerUser = asyncHandler(async (req, res) => {
  const { name, email, password } = req.body;

  //validation
  if (!name || !email || !password) {
    res.status(400);
    throw new Error("Please fill in all the required fields");
  }

  if (password.length < 6) {
    res.status(400);
    throw new Error("password must be up to 6 characters");
  }

  //check for existing user
  const userExists = await User.findOne({ email });

  if (userExists) {
    res.status(400);
    throw new Error("Email already registered");
  }

  //Get userAgent
  const ua = parser(req.headers["user-agent"]);
  const userAgent = [ua.ua];
  //creae new user
  const user = await User.create({
    name,
    email,
    password,
    userAgent,
  });

  //generate token
  const token = generateToken(user._id);

  //send HTTP-only cookie
  res.cookie("token", token, {
    path: "/",
    httpOnly: true,
    expires: new Date(Date.now() + 1000 * 86400), //1day
    sameSite: "none",
    secure: true,
  });
  if (user) {
    const { _id, name, email, phone, bio, photo, role, isVerified } = user;

    res
      .status(201)
      .json({ _id, name, email, phone, bio, photo, role, isVerified, token });
  } else {
    res.status(400);
    throw new Error("Invalid User Data");
  }
});

const loginUser = asyncHandler(async (req, res) => {
  const { email, password } = req.body;
  //vlaidation
  if (!email || !password) {
    res.status(400);
    throw new Error("please insert email and password");
  }

  const user = await User.findOne({ email });
  if (!user) {
    res.status(404);
    throw new Error("User not found please sign up");
  }

  const passwordIscorrect = await bcrypt.compare(password, user.password);

  if (!passwordIscorrect) {
    res.status(404);
    throw new Error("Invalid email or password");
  }

  //Triggrt 2FA for unknown user agent
  //Get userAgent
  const ua = parser(req.headers["user-agent"]);
  const thisuserAgent = ua.ua;
  console.log(thisuserAgent);

  const allowedAgent = user.userAgent.includes(thisuserAgent);

  if (!allowedAgent) {
    //generate 6 digit code
    const loginCode = Math.floor(100000 + Math.random() * 90000);

    console.log(loginCode);

    //Encrypt login code before saving to DB
    const encryptedLoginCode = cryptr.encrypt(loginCode.toString());

    //Delete Token if it exists in DB
    let userToken = await Token.findOne({ userId: user._id });
    if (userToken) {
      await userToken.deleteOne();
    }

    //Save  Token to DBt

    await new Token({
      userId: user._id,
      lToken: encryptedLoginCode,
      createdAt: Date.now(),
      expiresAt: Date.now() + 60 * (60 * 1000), //60 minutes
    }).save();

    res.status(400);
    throw new Error("New browser or device detected");
  }

  //generate token
  const token = generateToken(user._id);

  if (user && passwordIscorrect) {
    //send HTTP-only cookie
    res.cookie("token", token, {
      path: "/",
      httpOnly: true,
      expires: new Date(Date.now() + 1000 * 86400), //1day
      sameSite: "none",
      secure: true,
    });

    const { _id, name, email, phone, bio, photo, role, isVerified } = user;

    res
      .status(200)
      .json({ _id, name, email, phone, bio, photo, role, isVerified, token });
  } else {
    res.status(500);
    throw new Error("something went wong please try again");
  }
});

//send logincode
const sendLoginCode = asyncHandler(async (req, res) => {
  const { email } = req.params;
  const user = await User.findOne({ email });

  if (!user) {
    res.status(404);
    throw new Error("User not found");
  }

  //find login tokenin DB
  let userToken = await Token.findOne({
    userId: user._id,
    expiresAt: { $gt: Date.now() },
  });

  if (!userToken) {
    res.status(404);
    throw new Error("Invalid or Expired token, please login again");
  }

  const loginCode = userToken.lToken;

  //Decrypt login code before saving to DB
  const decryptedLoginCode = cryptr.decrypt(loginCode);

  //send email
  const subject = "Login Access Code";
  const sent_to = user.email;
  const sent_from = process.env.EMAIL_USER;
  const reply_to = "noreply@adordev.com";
  const template = "loginCode";
  const name = user.name;
  const link = decryptedLoginCode;

  try {
    await sendEmail(
      subject,
      sent_to,
      sent_from,
      reply_to,
      template,
      name,
      link
    );
    res.status(200).json({
      message: `Access Code sent to ${email}`,
    });
  } catch (error) {
    res.status(500);
    throw new Error("Email not sent please try again");
  }
});

const loginWithCode = asyncHandler(async (req, res) => {
  const { email } = req.params;
  const { loginCode } = req.body;

  const user = await User.findOne({ email });
  if (!user) {
    res.status(404);
    throw new Error("User not found");
  }
  //find user login token
  const userToken = await Token.findOne({
    userId: user.id,
    expiresAt: { $gt: Date.now() },
  });

  if (!userToken) {
    res.status(404);
    throw new Error("Invalid or Expired Token, please login again");
  }
  //Decrypt login code before saving to DB
  const decryptedLoginCode = cryptr.decrypt(userToken.lToken);

  if (loginCode !== decryptedLoginCode) {
    res.status(400);
    throw new Error("Incorrect Login Code, Please try again");
  } else {
    //Register UserAgent
    const ua = parser(req.headers["user-agent"]);
    const thisuserAgent = ua.ua;

    user.userAgent.push(thisuserAgent);
    await user.save();

    //login user in directly
    //generate token
    const token = generateToken(user._id);

    //send HTTP-only cookie
    res.cookie("token", token, {
      path: "/",
      httpOnly: true,
      expires: new Date(Date.now() + 1000 * 86400), //1day
      sameSite: "none",
      secure: true,
    });

    const { _id, name, email, phone, bio, photo, role, isVerified } = user;

    res
      .status(201)
      .json({ _id, name, email, phone, bio, photo, role, isVerified, token });
  }
});

//send verification email
const sendVerificationEmail = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);
  if (!user) {
    res.status(404);
    throw new Error("User not found ");
  }
  if (user.isVerified) {
    res.status(404);
    throw new Error("User already verified ");
  }
  //Delete Token if it exists in DB
  let token = await Token.findOne({ userId: user._id });
  if (token) {
    await token.deleteOne();
  }

  //create verification token and save
  const verificationToken = crypto.randomBytes(32).toString("hex") + user._id;
  console.log(verificationToken);

  //Hash Token and save it
  const hashedToken = hashToken(verificationToken);

  await new Token({
    userId: user._id,
    vToken: hashedToken,
    createdAt: Date.now(),
    expiresAt: Date.now() + 60 * (60 * 1000), //60 minutes
  }).save();

  //construct verification URL
  const verificationUrl = `${process.env.FRONTEND_URL}/verify/${verificationToken}`;

  //send email
  const subject = "Verify Your Account - Auth: Z";
  const sent_to = user.email;
  const sent_from = process.env.EMAIL_USER;
  const reply_to = "noreply@adordev.com";
  const template = "email";
  const name = user.name;
  const link = verificationUrl;

  try {
    await sendEmail(
      subject,
      sent_to,
      sent_from,
      reply_to,
      template,
      name,
      link
    );
    res.status(200).json({
      message: "Verification Email Sent",
    });
  } catch (error) {
    res.status(500);
    throw new Error("Email not sent please try again");
  }
});

//verify user
const verifyUser = asyncHandler(async (req, res) => {
  const { verificationToken } = req.params;

  //hash token before u look for it in db
  const hashedToken = hashToken(verificationToken);

  const userToken = await Token.findOne({
    vToken: hashedToken,
    expiresAt: { $gt: Date.now() },
  });
  if (!userToken) {
    res.status(404);
    throw new Error("Invalid or Expired Token");
  }

  //find User
  const user = await User.findOne({ _id: userToken.userId });

  if (user.isVerified) {
    res.status(400);
    throw new Error("User is already verified");
  }

  //Now verify user
  user.isVerified = true;
  await user.save();

  res.status(200).json({
    message: "Account Verification Succeessful",
  });
});

//logoutUser
const logoutUser = asyncHandler(async (req, res) => {
  res.cookie("token", "", {
    path: "/",
    httpOnly: true,
    expires: new Date(0), //expires cookie immediately
    sameSite: "none",
    secure: true,
  });
  return res.status(200).json({ message: "Successfully logged out" });
});

//fetch user
const getUser = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);

  if (user) {
    const { _id, name, email, phone, bio, photo, role, isVerified } = user;

    res
      .status(200)
      .json({ _id, name, email, phone, bio, photo, role, isVerified });
  } else {
    res.status(404);
    throw new Error("User not found");
  }
});

const updateUser = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);
  if (user) {
    const { name, email, phone, bio, photo, role, isVerified } = user;

    user.email = email;
    user.name = req.body.name || name;
    user.phone = req.body.phone || phone;
    user.bio = req.body.bio || bio;
    user.photo = req.body.photo || photo;

    const updatedUser = await user.save();
    res.status(200).json({
      _id: updatedUser._id,
      name: updatedUser.name,
      email: updatedUser.email,
      phone: updatedUser.phone,
      bio: updatedUser.bio,
      photo: updatedUser.photo,
      role: updatedUser.role,
      isVerified: updatedUser.isVerified,
    });
  } else {
    res.status(404);
    throw new Error("User not found");
  }
});

const deleteUser = asyncHandler(async (req, res) => {
  const user = User.findById(req.params.id);

  if (!user) {
    res.status(404);
    throw new Error("User not found");
  }
  await user.findOneAndRemove();
  res.status(200).json({
    message: "User delected successfully",
  });
});

const getUsers = asyncHandler(async (req, res) => {
  const users = await User.find().sort("-createdAt").select("-password");
  if (!users) {
    res.status(500);
    throw new Error("Something went wrong");
  }
  res.status(200).json(users);
});

const loginStatus = asyncHandler(async (req, res) => {
  const token = req.cookies.token;
  if (!token) {
    return res.json(false);
  }
  //verify token
  const verified = jwt.verify(token, process.env.JWT_SECRET);
  if (verified) {
    return res.json(true);
  }
  return res.json(false);
});

const upgradeUser = asyncHandler(async (req, res) => {
  const { role, id } = req.body;
  const user = await User.findById(id);
  if (!user) {
    res.status(404);
    throw new Error("User not found");
  }

  user.role = role;
  await user.save();

  res.status(200).json({
    message: `User role updated to ${role}`,
  });
});

const sendAutomatedEmail = asyncHandler(async (req, res) => {
  const { subject, sent_to, reply_to, template, url } = req.body;
  if (!subject || !sent_to || !reply_to || !template) {
    res.status(500);
    throw new Error("missing email parameter");
  }

  //Get user
  const user = await User.findOne({ email: sent_to });
  if (!user) {
    res.status(404);
    throw new Error("User not found");
  }

  const sent_from = process.env.EMAIL_USER;
  const name = user.name;
  const link = `${process.env.FRONTEND_URL}${url};`;

  try {
    await sendEmail(
      subject,
      sent_to,
      sent_from,
      reply_to,
      template,
      name,
      link
    );
    res.status(200).json({
      message: "Email Sent",
    });
  } catch (error) {
    res.status(500);
    throw new Error("Eemail not sent please try again");
  }
});

//forgot password
const forgotpassword = asyncHandler(async (req, res) => {
  const { email } = req.body;

  const user = await User.findOne({ email });
  if (!user) {
    res.status(404);
    throw new Error("No user with this email ");
  }

  //Delete Token if it exists in DB
  let token = await Token.findOne({ userId: user._id });
  if (token) {
    await token.deleteOne();
  }

  //create verification token and save
  const resetToken = crypto.randomBytes(32).toString("hex") + user._id;
  console.log(resetToken);

  //Hash Token and save it
  const hashedToken = hashToken(resetToken);

  await new Token({
    userId: user._id,
    rToken: hashedToken,
    createdAt: Date.now(),
    expiresAt: Date.now() + 60 * (60 * 1000), //60 minutes
  }).save();

  //construct reset URL
  const resetUrl = `${process.env.FRONTEND_URL}/resetpassword/${resetToken}`;

  //send email
  const subject = "Password Reset Request - Auth: Z";
  const sent_to = user.email;
  const sent_from = process.env.EMAIL_USER;
  const reply_to = "noreply@adordev.com";
  const template = "forgotPassword";
  const name = user.name;
  const link = resetUrl;

  try {
    await sendEmail(
      subject,
      sent_to,
      sent_from,
      reply_to,
      template,
      name,
      link
    );
    res.status(200).json({
      message: "Password Reset  Email Sent",
    });
  } catch (error) {
    res.status(500);
    throw new Error("Email not sent please try again");
  }
});

//Reset Password
const resetPassword = asyncHandler(async (req, res) => {
  const { resetToken } = req.params;
  const { password } = req.body;

  //hash token before u look for it in db
  const hashedToken = hashToken(resetToken);

  const userToken = await Token.findOne({
    rToken: hashedToken,
    expiresAt: { $gt: Date.now() },
  });
  if (!userToken) {
    res.status(404);
    throw new Error("Invalid or Expired Token");
  }

  //find User
  const user = await User.findOne({ _id: userToken.userId });

  //Now reset passwrd
  user.password = password;
  await user.save();

  res.status(200).json({
    message: "Password Reset Succeessful, Please login",
  });
});

//Change Password
const changePassword = asyncHandler(async (req, res) => {
  const { oldPassword, password } = req.body;
  const user = await User.findById(req.user._id);
  if (!user) {
    res.status(404);
    throw new Error("User not found ");
  }
  if (!oldPassword || !password) {
    res.status(400);
    throw new Error("Please enter old and new password");
  }

  //check if old password is correct
  const passwordIscorrect = await bcrypt.compare(oldPassword, user.password);
  //save new password
  if (user && passwordIscorrect) {
    user.password = password;
    await user.save();

    res
      .status(200)
      .json({ message: "Password change successful, please re-login" });
  } else {
    res.status(400);
    throw new Error("Old Password is incorect");
  }
});

//loginwithgoogle
const loginWithGoogle = asyncHandler(async (req, res) => {
  const { userToken } = req.body;
  // console.log(userToken);

  const ticket = await client.verifyIdToken({
    idToken: userToken,
    audience: process.env.GOOGLE_CLIENT_ID,
  });

  const payload = ticket.getPayload();
  const { name, email, picture, sub } = payload;
  const password = Date.now() + sub;
  //Get userAgent
  const ua = parser(req.headers["user-agent"]);
  const userAgent = [ua.ua];

  //check if user exist
  const user = await User.findOne({ email });
  if (!user) {
    //creae new user
    const newuser = await User.create({
      name,
      email,
      password,
      photo: picture,
      isVerified: true,
      userAgent,
    });

    if (newuser) {
      //generate token
      const token = generateToken(newuser._id);

      //send HTTP-only cookie
      res.cookie("token", token, {
        path: "/",
        httpOnly: true,
        expires: new Date(Date.now() + 1000 * 86400), //1day
        sameSite: "none",
        secure: true,
      });

      const {  name, email, phone, bio, photo, role, isVerified } = newuser;

      res.status(201).json({
        name,
        email,
        phone,
        bio,
        photo,
        role,
        isVerified,
        token,
      });
    } else {
      res.status(400);
      throw new Error("Invalid User Data");
    }
  }
//user exists, login
if(user){
  //generate token
  const token = generateToken(user._id);

  //send HTTP-only cookie
  res.cookie("token", token, {
    path: "/",
    httpOnly: true,
    expires: new Date(Date.now() + 1000 * 86400), //1day
    sameSite: "none",
    secure: true,
  });

  const { name, email, phone, bio, photo, role, isVerified } = user;

  res.status(201).json({
    name,
    email,
    phone,
    bio,
    photo,
    role,
    isVerified,
    token,
  });
}

});

export {
  registerUser,
  loginUser,
  logoutUser,
  getUser,
  updateUser,
  deleteUser,
  getUsers,
  loginStatus,
  upgradeUser,
  sendAutomatedEmail,
  sendVerificationEmail,
  verifyUser,
  forgotpassword,
  resetPassword,
  changePassword,
  sendLoginCode,
  loginWithCode,
  loginWithGoogle,
};
