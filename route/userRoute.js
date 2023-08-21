import express from "express";
import {
  deleteUser,
  getUser,
  getUsers,
  loginUser,
  loginStatus,
  logoutUser,
  registerUser,
  updateUser,
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
} from "../controllers/userController.js";
import { protect } from "../middleware/authMiddleware.js";
import { adminOnly, authorOnly } from "../utils/index.js";
const router = express.Router()

router.post("/register", registerUser )
router.post("/login",  loginUser)
router.get("/logout", logoutUser )
router.get("/getuser",protect, getUser);
router.patch("/updateuser",protect, updateUser);


router.delete("/:id", protect, adminOnly, deleteUser);
router.get("/getusers", protect, authorOnly, getUsers  );
router.get("/loggedin", loginStatus);
router.post("/upgradeuser", protect, adminOnly, upgradeUser);
router.post("/sendautomatedemail", protect, sendAutomatedEmail);


router.post("/sendverificationemail", protect, sendVerificationEmail );
router.patch("/verifyuser/:verificationToken", verifyUser);
router.post("/forgotpassword", forgotpassword);
router.patch("/resetpassword/:resetToken", resetPassword );
router.patch("/changepassword", protect, changePassword );


router.post("/sendlogincode/:email",  sendLoginCode );
router.post("/loginwithcode/:email", loginWithCode );

router.post("/google/callback", loginWithGoogle);






export default router