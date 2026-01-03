import express from "express";
import { login, logout, me } from "../controllers/auth.controllers.js";
import { verifyUser } from "../middlewares/auth.middleware.js";

const router = express.Router();

router.post("/login", login);
router.get("/me", verifyUser, me);
router.post("/logout", verifyUser, logout);

export default router;
