import express from "express";
import login from "./login.js";
import signup from "./signup.js";
import logout from "./logout.js";
import me from "./me.js";

const router = express.Router();

router.use("/login", login);
router.use("/signup", signup);
router.use("/logout", logout);
router.use("/me", me);

export default router;
