const express = require("express");
require("dotenv").config();
const cors = require("cors");
const mongoose = require("mongoose");

const app = express();
const port = process.env.PORT || 5000;

app.use(
  cors({
    origin: process.env.CLIENT_ORIGIN?.split(",") || "*",
    credentials: true,
  }),
);
app.use(express.json());

const roles = ["patient", "doctor", "admin"];

const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      index: true,
    },
    passwordHash: String,
    role: { type: String, enum: roles, default: "patient", index: true },
    photo: String,
    phone: String,
    gender: String,
    status: {
      type: String,
      enum: ["active", "suspended"],
      default: "active",
      index: true,
    },
    provider: { type: String, default: "credentials" },
  },
  { timestamps: true, strict: false },
);

const User = mongoose.models.User || mongoose.model("User", userSchema);

const appointmentSchema = new mongoose.Schema(
  {
    patient: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    doctor: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Doctor",
      required: true,
      index: true,
    },
    date: { type: Date, required: true, index: true },
    time: { type: String, required: true, trim: true },
    symptoms: { type: String, trim: true },
    status: {
      type: String,
      enum: [
        "requested",
        "accepted",
        "rejected",
        "rescheduled",
        "cancelled",
        "completed",
      ],
      default: "requested",
      index: true,
    },
    paymentStatus: {
      type: String,
      enum: ["unpaid", "pending", "paid", "refunded", "failed"],
      default: "unpaid",
      index: true,
    },
    amount: { type: Number, required: true, min: 0 },
  },
  { timestamps: true },
);

const Appointment =
  mongoose.models.Appointment ||
  mongoose.model("Appointment", appointmentSchema);

const reviewSchema = new mongoose.Schema(
  {
    patient: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    doctor: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Doctor",
      required: true,
      index: true,
    },
    rating: { type: Number, required: true, min: 1, max: 5 },
    comment: { type: String, required: true, trim: true },
  },
  { timestamps: true },
);

const paymentSchema = new mongoose.Schema(
  {
    appointment: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Appointment",
      required: true,
      index: true,
    },
    patient: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    doctor: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Doctor",
      required: true,
      index: true,
    },
    amount: { type: Number, required: true, min: 0 },
    currency: { type: String, default: "usd" },
    transactionId: { type: String, required: true, index: true },
    provider: { type: String, default: "stripe" },
    status: {
      type: String,
      enum: ["pending", "paid", "failed", "refunded"],
      default: "pending",
      index: true,
    },
    paidAt: Date,
  },
  { timestamps: true, strict: false },
);

const prescriptionSchema = new mongoose.Schema(
  {
    appointment: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Appointment",
      required: true,
      index: true,
    },
    patient: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    doctor: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Doctor",
      required: true,
      index: true,
    },
    diagnosis: { type: String, required: true, trim: true },
    medications: [
      {
        name: { type: String, required: true, trim: true },
        dosage: { type: String, required: true, trim: true },
        duration: { type: String, trim: true },
        instructions: { type: String, trim: true },
      },
    ],
    notes: { type: String, trim: true },
  },
  { timestamps: true },
);

const Review = mongoose.models.Review || mongoose.model("Review", reviewSchema);
const Payment =
  mongoose.models.Payment || mongoose.model("Payment", paymentSchema);
const Prescription =
  mongoose.models.Prescription ||
  mongoose.model("Prescription", prescriptionSchema);

app.get("/", (_req, res) => {
  res.send("MediCare Connect API is healthy");
});

const connectDB = async () => {
  const mongoUri = process.env.MONGO_DB_URI;
  if (!mongoUri) throw new Error("Missing environment variable: MONGO_DB_URI");

  await mongoose.connect(mongoUri, { dbName: "medicare_connect" });
  console.log("MongoDB connected");
};

connectDB()
  .then(() => {
    app.listen(port, () => {
      console.log(`MediCare Connect API running on http://localhost:${port}`);
    });
  })
  .catch((error) => {
    console.error("MongoDB connection failed:", error.message);
    process.exit(1);
  });

module.exports = app;
