import User from "../models/user.models.js";
import Session from "../models/session.models.js";
import crypto from "crypto";

const MAX_DEVICES = 2;

export const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const deviceId = req.deviceId; // injected by middleware

    const user = await User.findOne({ email })
      .select("+password")
      .populate("role");

    if (!user || user.status !== "active") {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    // 1. Check for existing valid session on SAME device
    const existingSession = await Session.findOne({
      user: user._id,
      deviceId,
      isValid: true,
      expiresAt: { $gt: new Date() }
    });

    if (existingSession) {
      // Reuse session
      res.cookie("session", existingSession.sessionToken, {
        httpOnly: true,
        signed: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        maxAge: 7 * 24 * 60 * 60 * 1000
      });

      return res.json({
        success: true,
        reusedSession: true,
        user: {
          id: user._id,
          fullName: user.fullName,
          role: user.role.name
        }
      });
    }

    // 2. Enforce device limit ONLY for new device
    const activeSessions = await Session.find({
      user: user._id,
      isValid: true,
      expiresAt: { $gt: new Date() }
    }).sort({ createdAt: 1 });

    if (activeSessions.length >= MAX_DEVICES) {
      const sessionsToInvalidate = activeSessions.slice(
        0,
        activeSessions.length - MAX_DEVICES + 1
      );

      await Session.updateMany(
        { _id: { $in: sessionsToInvalidate.map(s => s._id) } },
        { isValid: false }
      );
    }

    // 3. Create new session for new device
    const sessionToken = crypto.randomBytes(32).toString("hex");

    await Session.create({
      user: user._id,
      sessionToken,
      deviceId,
      role: user.role._id,
      ipAddress: req.ip,
      userAgent: req.headers["user-agent"],
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
    });

    res.cookie("session", sessionToken, {
      httpOnly: true,
      signed: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    res.json({
      success: true,
      reusedSession: false,
      user: {
        id: user._id,
        fullName: user.fullName,
        role: user.role.name
      }
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ message: "Login failed" });
  }
};

export const me = async (req, res) => {
  const user = req.user;

  res.json({
    user: {
      id: user._id,
      fullName: user.fullName,
      role: user.role.name,
    },
  });
};

export const logout = async (req, res) => {
  await Session.updateOne(
    { sessionToken: req.sessionToken },
    { isValid: false }
  );

  res.clearCookie("session");
  res.json({ success: true });
};
