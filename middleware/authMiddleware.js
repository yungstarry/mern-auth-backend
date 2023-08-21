import asyncHandler from "express-async-handler";
import jwt from "jsonwebtoken";
import User from "../model/userModel.js";

const protect = asyncHandler(async (req, res, next) => {
  try {
    const token = req.cookies.token;
    if (!token) {
       res.status(401);
      throw new Error("Not authorised. please login");
    }
    //verify token
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    //get user id from token
    const user = await User.findById(verified.id).select("-password");

    if (!user) {
      res.status(404).json({ message: "User Not Found" });
    }
    if (user.role === "suspended") {
      res.status(400);
      throw new Error("User Suspended pleease contact support");
    }

    req.user = user
    next()
  } catch (error) {
     res.status(401);
    throw new Error("Not authorised. please login");
  }
});





export {protect}
