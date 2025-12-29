import Session from "../models/session.models.js";

export const verifyUser = async (req, res, next) => {
  try {
    const sessionToken = req.signedCookies?.session;

    if (!sessionToken) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const session = await Session.findOne({
      sessionToken,
      isValid: true,
      expiresAt: { $gt: new Date() }
    }).populate("user role");

    if (!session) {
      return res.status(401).json({ message: "Invalid or expired session" });
    }

    if (session.user.status !== "active") {
      session.isValid = false;
      await session.save();
      return res.status(403).json({ message: "User inactive" });
    }

    // Trusted auth context
    req.user = session.user;
    req.role = session.role;
    req.session = session;

    next();
  } catch (err) {
    console.error("verifyUser error:", err);
    res.status(500).json({ message: "Authentication failed" });
  }
};

/**
 * Role-based authorization - why params? still looking into it
 * @param {...string} allowedRoles
 */
export const checkRole = (...allowedRoles) => {
  return (req, res, next) => {
    const roleName = req.role?.name;

    if (!roleName) {
      return res.status(403).json({ message: "Access denied" });
    }

    if (!allowedRoles.includes(roleName)) {
      return res.status(403).json({
        message: "Insufficient permissions"
      });
    }

    next();
  };
};
