import express from "express";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";
import cors from "cors";

import connectDB from "./config/db.js";
import { ensureDeviceId } from "./middlewares/device.middleware.js";
import { verifyUser } from "./middlewares/auth.middleware.js";

import authRoutes from "./routes/auth.routes.js";
import clientRoutes from "./routes/client.routes.js";
import contactRoutes from "./routes/contacts.routes.js";
import leadRoutes from "./routes/lead.routes.js";
import leadManagementRoutes from "./routes/leadManagement.routes.js";
import permissionRoutes from "./routes/permission.routes.js";
import roleRoutes from "./routes/role.routes.js";
import userRoutes from "./routes/user.routes.js";

dotenv.config();
connectDB();

const app = express();

app.use(cors({
  origin: "http://localhost:3000",
  credentials: true,
}));

app.use(express.json());
app.use(cookieParser(process.env.COOKIE_SECRET));

app.use(ensureDeviceId);

app.get("/", (req, res) => {
  res.send("Server running...");
});

app.use("/api/auth", authRoutes);

app.use(verifyUser);

app.use("/api/clients", clientRoutes);
app.use("/api/contacts", contactRoutes);
app.use("/api/leads", leadRoutes);
app.use("/api/leads/manage", leadManagementRoutes);
app.use("/api/permissions", permissionRoutes);
app.use("/api/roles", roleRoutes);
app.use("/api/users", userRoutes);

const PORT = process.env.PORT || 5000;
app.listen(PORT, () =>
  console.log(`Server running on port ${PORT}`)
);
