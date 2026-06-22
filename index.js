const express = require("express");
require("dotenv").config();
const bcrypt = require("bcryptjs");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const Stripe = require("stripe");

const app = express();
const port = process.env.PORT || 5000;
const stripe = process.env.STRIPE_SECRET_KEY
  ? new Stripe(process.env.STRIPE_SECRET_KEY)
  : null;

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

const signToken = (user) =>
  jwt.sign(
    { sub: user._id.toString(), role: user.role, email: user.email },
    process.env.JWT_SECRET || "dev-only-secret-change-me",
    { expiresIn: process.env.JWT_EXPIRES_IN || "7d" },
  );

const publicUser = (user) => {
  const plain = typeof user.toObject === "function" ? user.toObject() : { ...user };
  delete plain.passwordHash;
  return { ...plain, id: plain._id?.toString() };
};

const verifyToken = async (req, res, next) => {
  try {
    const header = req.headers.authorization;
    const token = header?.startsWith("Bearer ") ? header.slice(7) : null;

    if (!token) return res.status(401).json({ message: "Unauthorized" });

    const payload = jwt.verify(
      token,
      process.env.JWT_SECRET || "dev-only-secret-change-me",
    );
    const user = await User.findById(payload.sub);

    if (!user || user.status === "suspended") {
      return res.status(401).json({ message: "Unauthorized" });
    }

    req.user = user;
    next();
  } catch (error) {
    return res.status(401).json({ message: "Unauthorized", error: error.message });
  }
};

const verifyRole = (...allowedRoles) => (req, res, next) => {
  if (!allowedRoles.includes(req.user?.role)) {
    return res.status(403).json({ message: "Forbidden" });
  }

  next();
};

const strongPassword = /^(?=.*\d)(?=.*[!@#$%^&*()_\-+=[\]{};':"\\|,.<>/?]).{6,}$/;

const pick = (source, fields) =>
  fields.reduce((result, field) => {
    if (source[field] !== undefined) result[field] = source[field];
    return result;
  }, {});

app.get("/", (_req, res) => {
  res.send("MediCare Connect API is healthy");
});

app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password, role = "patient" } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ message: "Name, email, and password are required" });
    }
    if (!roles.includes(role) || role === "admin") {
      return res.status(400).json({ message: "Invalid registration role" });
    }
    if (!strongPassword.test(password)) {
      return res.status(400).json({
        message:
          "Password must be at least 6 characters and include a number and special character",
      });
    }

    const normalizedEmail = email.toLowerCase();
    const existing = await User.findOne({ email: normalizedEmail });
    if (existing) return res.status(409).json({ message: "Email already exists" });

    const passwordHash = await bcrypt.hash(password, 10);
    const user = await User.create({
      ...pick(req.body, ["name", "photo", "phone", "gender"]),
      email: normalizedEmail,
      passwordHash,
      role,
    });

    if (role === "doctor") {
      await mongoose.connection.collection("doctors").insertOne({
        user: user._id,
        specialization: req.body.specialization || "General Medicine",
        qualifications: req.body.qualifications || "MBBS",
        experience: Number(req.body.experience || 0),
        consultationFee: Number(req.body.consultationFee || 50),
        hospital: req.body.hospital || "MediCare Partner Hospital",
        image: req.body.photo || "",
        days: req.body.days || ["Monday", "Wednesday"],
        slots: req.body.slots || ["10:00 AM", "02:00 PM"],
        verificationStatus: "pending",
        createdAt: new Date(),
        updatedAt: new Date(),
      });
    }

    res.status(201).json({ user: publicUser(user), token: signToken(user) });
  } catch (error) {
    console.error("[auth:register]", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email: String(email).toLowerCase() });

    if (!user || !user.passwordHash) {
      return res.status(401).json({ message: "Invalid email or password" });
    }
    if (user.status === "suspended") {
      return res.status(403).json({ message: "Account is suspended" });
    }

    const valid = await bcrypt.compare(password || "", user.passwordHash);
    if (!valid) return res.status(401).json({ message: "Invalid email or password" });

    res.json({ user: publicUser(user), token: signToken(user) });
  } catch (error) {
    console.error("[auth:login]", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

app.post("/api/auth/google", async (req, res) => {
  try {
    const { email, name, photo, role = "patient" } = req.body;

    if (!email || !name) {
      return res.status(400).json({ message: "Google profile is required" });
    }

    const normalizedEmail = email.toLowerCase();
    const requestedRole = roles.includes(role) && role !== "admin" ? role : "patient";
    const user = await User.findOneAndUpdate(
      { email: normalizedEmail },
      {
        $setOnInsert: {
          email: normalizedEmail,
          role: requestedRole,
          provider: "google",
        },
        $set: { name, photo },
      },
      { new: true, upsert: true, setDefaultsOnInsert: true },
    );

    if (user.status === "suspended") {
      return res.status(403).json({ message: "Account is suspended" });
    }

    if (user.role === "doctor") {
      const existingProfile = await mongoose.connection
        .collection("doctors")
        .findOne({ user: user._id });

      if (!existingProfile) {
        await mongoose.connection.collection("doctors").insertOne({
          user: user._id,
          specialization: req.body.specialization || "General Medicine",
          qualifications: req.body.qualifications || "MBBS",
          experience: Number(req.body.experience || 0),
          consultationFee: Number(req.body.consultationFee || 50),
          hospital: req.body.hospital || "MediCare Partner Hospital",
          image: photo || "",
          days: req.body.days || ["Monday"],
          slots: req.body.slots || ["10:00 AM"],
          verificationStatus: "pending",
          createdAt: new Date(),
          updatedAt: new Date(),
        });
      }
    }

    res.json({ user: publicUser(user), token: signToken(user) });
  } catch (error) {
    console.error("[auth:google]", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

app.get("/api/auth/me", verifyToken, async (req, res) => {
  res.json(publicUser(req.user));
});

app.patch("/api/users/me", verifyToken, async (req, res) => {
  try {
    const updates = pick(req.body, ["name", "photo", "phone", "gender"]);
    const user = await User.findByIdAndUpdate(req.user._id, updates, { new: true });
    res.json(publicUser(user));
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

app.get("/api/users", verifyToken, verifyRole("admin"), async (_req, res) => {
  try {
    const users = await User.find({}).sort({ createdAt: -1 });
    res.json(users.map(publicUser));
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

app.patch(
  "/api/users/:id/status",
  verifyToken,
  verifyRole("admin"),
  async (req, res) => {
    try {
      if (!["active", "suspended"].includes(req.body.status)) {
        return res.status(400).json({ message: "Invalid status" });
      }

      const user = await User.findByIdAndUpdate(
        req.params.id,
        { status: req.body.status },
        { new: true },
      );

      if (!user) return res.status(404).json({ message: "User not found" });

      res.json(publicUser(user));
    } catch (error) {
      res.status(500).json({ message: "Server error", error: error.message });
    }
  },
);

app.delete("/api/users/:id", verifyToken, verifyRole("admin"), async (req, res) => {
  try {
    const user = await User.findByIdAndDelete(req.params.id);
    if (!user) return res.status(404).json({ message: "User not found" });

    res.json({ message: "User deleted" });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

const toObjectId = (id) => {
  if (!mongoose.Types.ObjectId.isValid(id)) return null;
  return new mongoose.Types.ObjectId(id);
};

const serializeDoctor = (doctor) => {
  if (!doctor) return null;
  const safeDoctor = { ...doctor };

  if (safeDoctor.userProfile) {
    delete safeDoctor.userProfile.passwordHash;
  }

  return {
    ...safeDoctor,
    id: doctor._id?.toString(),
    _id: doctor._id?.toString(),
    user: doctor.user?.toString?.() || doctor.user,
  };
};

const doctorSort = (value) => {
  if (value === "fee_asc") return { consultationFee: 1 };
  if (value === "fee_desc") return { consultationFee: -1 };
  if (value === "experience") return { experience: -1 };
  if (value === "rating") return { ratingAverage: -1, rating: -1 };
  return { createdAt: -1 };
};

const buildDoctorSearchMatch = (query) => {
  const match = {};

  if (query.status) match.verificationStatus = query.status;
  if (query.specialization) {
    match.specialization = { $regex: query.specialization, $options: "i" };
  }
  if (query.search) {
    match.$or = [
      { doctorName: { $regex: query.search, $options: "i" } },
      { specialization: { $regex: query.search, $options: "i" } },
    ];
  }

  return match;
};

app.get("/api/doctors", async (req, res) => {
  try {
    const page = Math.max(parseInt(req.query.page, 10) || 1, 1);
    const perPage = Math.min(Math.max(parseInt(req.query.perPage, 10) || 9, 1), 50);
    const skip = (page - 1) * perPage;
    const match = buildDoctorSearchMatch(req.query);

    if (!req.query.includeUnverified) {
      match.verificationStatus = match.verificationStatus || "verified";
    }

    const pipeline = [
      {
        $lookup: {
          from: "users",
          localField: "user",
          foreignField: "_id",
          as: "userProfile",
        },
      },
      { $unwind: { path: "$userProfile", preserveNullAndEmptyArrays: true } },
      {
        $addFields: {
          doctorName: { $ifNull: ["$doctorName", "$userProfile.name"] },
          profileImage: { $ifNull: ["$image", "$userProfile.photo"] },
        },
      },
      { $match: match },
      {
        $facet: {
          doctors: [{ $sort: doctorSort(req.query.sort) }, { $skip: skip }, { $limit: perPage }],
          total: [{ $count: "count" }],
        },
      },
    ];

    const [result] = await mongoose.connection.collection("doctors").aggregate(pipeline).toArray();
    const doctors = result.doctors.map(serializeDoctor);
    const total = result.total[0]?.count || 0;

    res.json({ total, page, perPage, doctors });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

app.get("/api/doctors/me", verifyToken, verifyRole("doctor"), async (req, res) => {
  try {
    const doctor = await mongoose.connection
      .collection("doctors")
      .findOne({ user: req.user._id });

    if (!doctor) return res.status(404).json({ message: "Doctor profile not found" });

    res.json(serializeDoctor(doctor));
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

app.get("/api/doctors/:id", async (req, res) => {
  try {
    const doctorId = toObjectId(req.params.id);
    if (!doctorId) return res.status(400).json({ message: "Invalid doctor id" });

    const [doctor] = await mongoose.connection
      .collection("doctors")
      .aggregate([
        { $match: { _id: doctorId } },
        {
          $lookup: {
            from: "users",
            localField: "user",
            foreignField: "_id",
            as: "userProfile",
          },
        },
        { $unwind: { path: "$userProfile", preserveNullAndEmptyArrays: true } },
        {
          $addFields: {
            doctorName: { $ifNull: ["$doctorName", "$userProfile.name"] },
            profileImage: { $ifNull: ["$image", "$userProfile.photo"] },
          },
        },
      ])
      .toArray();

    if (!doctor) return res.status(404).json({ message: "Doctor not found" });

    res.json(serializeDoctor(doctor));
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

app.patch(
  "/api/doctors/:id/verification",
  verifyToken,
  verifyRole("admin"),
  async (req, res) => {
    try {
      if (!["pending", "verified", "rejected"].includes(req.body.verificationStatus)) {
        return res.status(400).json({ message: "Invalid verification status" });
      }

      const doctorId = toObjectId(req.params.id);
      if (!doctorId) return res.status(400).json({ message: "Invalid doctor id" });

      const result = await mongoose.connection.collection("doctors").findOneAndUpdate(
        { _id: doctorId },
        {
          $set: {
            verificationStatus: req.body.verificationStatus,
            updatedAt: new Date(),
          },
        },
        { returnDocument: "after" },
      );

      const doctor = result.value || result;
      if (!doctor) return res.status(404).json({ message: "Doctor not found" });

      res.json(serializeDoctor(doctor));
    } catch (error) {
      res.status(500).json({ message: "Server error", error: error.message });
    }
  },
);

const appointmentStatuses = [
  "requested",
  "accepted",
  "rejected",
  "rescheduled",
  "cancelled",
  "completed",
];

const findDoctorProfileForUser = async (userId) =>
  mongoose.connection.collection("doctors").findOne({ user: userId });

app.get("/api/appointments", verifyToken, async (req, res) => {
  try {
    const query = {};

    if (req.user.role === "patient") {
      query.patient = req.user._id;
    }

    if (req.user.role === "doctor") {
      const doctor = await findDoctorProfileForUser(req.user._id);
      query.doctor = doctor?._id || new mongoose.Types.ObjectId();
    }

    if (req.query.status) query.status = req.query.status;

    const appointments = await Appointment.find(query)
      .populate("patient", "name email photo phone gender")
      .sort({ date: 1, time: 1 });

    res.json(appointments);
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

app.post("/api/appointments", verifyToken, verifyRole("patient"), async (req, res) => {
  try {
    const doctorId = toObjectId(req.body.doctor || req.body.doctorId);
    if (!doctorId) return res.status(400).json({ message: "Invalid doctor id" });

    const doctor = await mongoose.connection.collection("doctors").findOne({
      _id: doctorId,
      verificationStatus: "verified",
    });

    if (!doctor) return res.status(404).json({ message: "Doctor not available" });
    if (!req.body.date || !req.body.time) {
      return res.status(400).json({ message: "Date and time are required" });
    }

    const appointment = await Appointment.create({
      patient: req.user._id,
      doctor: doctor._id,
      date: req.body.date,
      time: req.body.time,
      symptoms: req.body.symptoms,
      status: "requested",
      paymentStatus: "unpaid",
      amount: doctor.consultationFee || 0,
    });

    res.status(201).json(appointment);
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

app.patch("/api/appointments/:id", verifyToken, async (req, res) => {
  try {
    const appointment = await Appointment.findById(req.params.id);
    if (!appointment) return res.status(404).json({ message: "Appointment not found" });

    const isPatient = appointment.patient.toString() === req.user._id.toString();
    let isDoctor = false;

    if (req.user.role === "doctor") {
      const doctor = await findDoctorProfileForUser(req.user._id);
      isDoctor = doctor?._id?.toString() === appointment.doctor.toString();
    }

    if (req.user.role !== "admin" && !isPatient && !isDoctor) {
      return res.status(403).json({ message: "Forbidden" });
    }

    if (req.user.role === "patient") {
      if (!isPatient) return res.status(403).json({ message: "Forbidden" });

      const updates = pick(req.body, ["date", "time", "symptoms"]);
      if (req.body.status === "cancelled") {
        updates.status = "cancelled";
      } else if (updates.date || updates.time) {
        updates.status = "rescheduled";
      }

      Object.assign(appointment, updates);
    }

    if (req.user.role === "doctor" || req.user.role === "admin") {
      if (req.user.role === "doctor" && !isDoctor) {
        return res.status(403).json({ message: "Forbidden" });
      }
      if (req.body.status && appointmentStatuses.includes(req.body.status)) {
        appointment.status = req.body.status;
      }
    }

    await appointment.save();
    res.json(appointment);
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

const recalculateDoctorRating = async (doctorId) => {
  const result = await Review.aggregate([
    { $match: { doctor: doctorId } },
    {
      $group: {
        _id: "$doctor",
        average: { $avg: "$rating" },
        count: { $sum: 1 },
      },
    },
  ]);
  const stats = result[0] || { average: 0, count: 0 };

  await mongoose.connection.collection("doctors").updateOne(
    { _id: doctorId },
    {
      $set: {
        ratingAverage: Number((stats.average || 0).toFixed(1)),
        reviewCount: stats.count,
        updatedAt: new Date(),
      },
    },
  );
};

app.get("/api/reviews", async (req, res) => {
  try {
    const query = {};

    if (req.query.doctor || req.query.doctorId) {
      const doctorId = toObjectId(req.query.doctor || req.query.doctorId);
      if (!doctorId) return res.status(400).json({ message: "Invalid doctor id" });
      query.doctor = doctorId;
    }

    const reviews = await Review.find(query)
      .populate("patient", "name photo")
      .sort({ createdAt: -1 })
      .limit(50);

    res.json(reviews);
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

app.post("/api/reviews", verifyToken, verifyRole("patient"), async (req, res) => {
  try {
    const doctorId = toObjectId(req.body.doctor || req.body.doctorId);
    if (!doctorId) return res.status(400).json({ message: "Invalid doctor id" });

    const doctor = await mongoose.connection.collection("doctors").findOne({ _id: doctorId });
    if (!doctor) return res.status(404).json({ message: "Doctor not found" });

    const review = await Review.create({
      patient: req.user._id,
      doctor: doctor._id,
      rating: Number(req.body.rating),
      comment: req.body.comment,
    });

    await recalculateDoctorRating(doctor._id);
    res.status(201).json(review);
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

app.patch("/api/reviews/:id", verifyToken, async (req, res) => {
  try {
    const review = await Review.findById(req.params.id);
    if (!review) return res.status(404).json({ message: "Review not found" });

    const isOwner = review.patient.toString() === req.user._id.toString();
    if (req.user.role !== "admin" && !isOwner) {
      return res.status(403).json({ message: "Forbidden" });
    }

    Object.assign(review, pick(req.body, ["rating", "comment"]));
    await review.save();
    await recalculateDoctorRating(review.doctor);

    res.json(review);
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

app.delete("/api/reviews/:id", verifyToken, async (req, res) => {
  try {
    const review = await Review.findById(req.params.id);
    if (!review) return res.status(404).json({ message: "Review not found" });

    const isOwner = review.patient.toString() === req.user._id.toString();
    if (req.user.role !== "admin" && !isOwner) {
      return res.status(403).json({ message: "Forbidden" });
    }

    const doctorId = review.doctor;
    await review.deleteOne();
    await recalculateDoctorRating(doctorId);

    res.json({ message: "Review deleted" });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

app.get("/api/payments", verifyToken, async (req, res) => {
  try {
    const query = {};

    if (req.user.role === "patient") {
      query.patient = req.user._id;
    }

    if (req.user.role === "doctor") {
      const doctor = await findDoctorProfileForUser(req.user._id);
      query.doctor = doctor?._id || new mongoose.Types.ObjectId();
    }

    const payments = await Payment.find(query)
      .populate("patient", "name email")
      .populate("appointment")
      .sort({ createdAt: -1 });

    res.json(payments);
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

app.post(
  "/api/payments/create-intent",
  verifyToken,
  verifyRole("patient"),
  async (req, res) => {
    try {
      const appointment = await Appointment.findById(req.body.appointment || req.body.appointmentId);

      if (!appointment) {
        return res.status(404).json({ message: "Appointment not found" });
      }
      if (appointment.patient.toString() !== req.user._id.toString()) {
        return res.status(403).json({ message: "Forbidden" });
      }

      if (!stripe) {
        return res.json({
          clientSecret: "demo_client_secret",
          transactionId: `demo_${Date.now()}`,
          demo: true,
        });
      }

      const intent = await stripe.paymentIntents.create({
        amount: Math.round(appointment.amount * 100),
        currency: "usd",
        metadata: {
          appointmentId: appointment._id.toString(),
          patientId: appointment.patient.toString(),
          doctorId: appointment.doctor.toString(),
        },
      });

      res.json({ clientSecret: intent.client_secret, transactionId: intent.id });
    } catch (error) {
      res.status(500).json({ message: "Server error", error: error.message });
    }
  },
);

app.post("/api/payments", verifyToken, verifyRole("patient", "admin"), async (req, res) => {
  try {
    const appointment = await Appointment.findById(req.body.appointment || req.body.appointmentId);

    if (!appointment) return res.status(404).json({ message: "Appointment not found" });
    if (req.user.role !== "admin" && appointment.patient.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: "Forbidden" });
    }

    const status = req.body.status || "paid";
    const payment = await Payment.create({
      appointment: appointment._id,
      patient: appointment.patient,
      doctor: appointment.doctor,
      amount: appointment.amount,
      currency: req.body.currency || "usd",
      transactionId: req.body.transactionId || `manual_${Date.now()}`,
      provider: req.body.provider || (stripe ? "stripe" : "demo"),
      status,
      paidAt: status === "paid" ? new Date() : undefined,
    });

    appointment.paymentStatus = status === "paid" ? "paid" : "pending";
    await appointment.save();

    res.status(201).json(payment);
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

app.get("/api/prescriptions", verifyToken, async (req, res) => {
  try {
    const query = {};

    if (req.user.role === "patient") {
      query.patient = req.user._id;
    }

    if (req.user.role === "doctor") {
      const doctor = await findDoctorProfileForUser(req.user._id);
      query.doctor = doctor?._id || new mongoose.Types.ObjectId();
    }

    if (req.query.appointment || req.query.appointmentId) {
      const appointmentId = toObjectId(req.query.appointment || req.query.appointmentId);
      if (!appointmentId) return res.status(400).json({ message: "Invalid appointment id" });
      query.appointment = appointmentId;
    }

    const prescriptions = await Prescription.find(query)
      .populate("patient", "name email photo phone gender")
      .populate("appointment")
      .sort({ createdAt: -1 });

    res.json(prescriptions);
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

app.post(
  "/api/prescriptions",
  verifyToken,
  verifyRole("doctor", "admin"),
  async (req, res) => {
    try {
      const appointment = await Appointment.findById(req.body.appointment || req.body.appointmentId);

      if (!appointment) {
        return res.status(404).json({ message: "Appointment not found" });
      }

      if (req.user.role === "doctor") {
        const doctor = await findDoctorProfileForUser(req.user._id);
        if (doctor?._id?.toString() !== appointment.doctor.toString()) {
          return res.status(403).json({ message: "Forbidden" });
        }
      }

      const prescription = await Prescription.create({
        appointment: appointment._id,
        patient: appointment.patient,
        doctor: appointment.doctor,
        diagnosis: req.body.diagnosis,
        medications: req.body.medications || [],
        notes: req.body.notes,
      });

      appointment.status = "completed";
      await appointment.save();

      res.status(201).json(prescription);
    } catch (error) {
      res.status(500).json({ message: "Server error", error: error.message });
    }
  },
);

app.patch(
  "/api/prescriptions/:id",
  verifyToken,
  verifyRole("doctor", "admin"),
  async (req, res) => {
    try {
      const prescription = await Prescription.findById(req.params.id);

      if (!prescription) {
        return res.status(404).json({ message: "Prescription not found" });
      }

      if (req.user.role === "doctor") {
        const doctor = await findDoctorProfileForUser(req.user._id);
        if (doctor?._id?.toString() !== prescription.doctor.toString()) {
          return res.status(403).json({ message: "Forbidden" });
        }
      }

      Object.assign(
        prescription,
        pick(req.body, ["diagnosis", "medications", "notes"]),
      );
      await prescription.save();

      res.json(prescription);
    } catch (error) {
      res.status(500).json({ message: "Server error", error: error.message });
    }
  },
);

app.get("/api/stats", async (_req, res) => {
  try {
    const [doctors, patients, appointments, reviews, slotStats] = await Promise.all([
      mongoose.connection
        .collection("doctors")
        .countDocuments({ verificationStatus: "verified" }),
      User.countDocuments({ role: "patient" }),
      Appointment.countDocuments(),
      Review.countDocuments(),
      mongoose.connection
        .collection("doctors")
        .aggregate([
          { $match: { verificationStatus: "verified" } },
          { $project: { slotCount: { $size: { $ifNull: ["$slots", []] } } } },
          { $group: { _id: null, total: { $sum: "$slotCount" } } },
        ])
        .toArray(),
    ]);

    res.json({
      doctors,
      patients,
      appointments,
      reviews,
      openSlots: slotStats[0]?.total || 0,
    });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

app.get("/api/analytics", verifyToken, verifyRole("admin"), async (_req, res) => {
  try {
    const [topDoctors, usersByRole, appointmentsByStatus, paymentsByStatus] =
      await Promise.all([
        mongoose.connection
          .collection("doctors")
          .find({})
          .sort({ ratingAverage: -1, reviewCount: -1 })
          .limit(10)
          .toArray(),
        User.aggregate([{ $group: { _id: "$role", count: { $sum: 1 } } }]),
        Appointment.aggregate([{ $group: { _id: "$status", count: { $sum: 1 } } }]),
        Payment.aggregate([
          {
            $group: {
              _id: "$status",
              count: { $sum: 1 },
              total: { $sum: "$amount" },
            },
          },
        ]),
      ]);

    res.json({
      topDoctors: topDoctors.map(serializeDoctor),
      usersByRole,
      appointmentsByStatus,
      paymentsByStatus,
    });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

const seedDemoData = async () => {
  if (process.env.SEED_DEMO_DATA === "false") return;

  const existingUsers = await User.estimatedDocumentCount();
  if (existingUsers > 0) return;

  const [adminPassword, patientPassword, doctorPassword] = await Promise.all([
    bcrypt.hash(process.env.ADMIN_PASSWORD || "Admin#12345", 10),
    bcrypt.hash("Patient#123", 10),
    bcrypt.hash("Doctor#123", 10),
  ]);

  const [admin, patient, doctorUser] = await User.create([
    {
      name: "MediCare Admin",
      email: process.env.ADMIN_EMAIL || "admin@medicare.test",
      passwordHash: adminPassword,
      role: "admin",
      photo:
        "https://images.unsplash.com/photo-1551836022-d5d88e9218df?auto=format&fit=crop&w=300&q=80",
    },
    {
      name: "Ariana Rahman",
      email: "patient@medicare.test",
      passwordHash: patientPassword,
      role: "patient",
      phone: "+1 555 0142",
      gender: "female",
      photo:
        "https://images.unsplash.com/photo-1494790108377-be9c29b29330?auto=format&fit=crop&w=300&q=80",
    },
    {
      name: "Dr. Mason Lee",
      email: "doctor@medicare.test",
      passwordHash: doctorPassword,
      role: "doctor",
      phone: "+1 555 0198",
      photo:
        "https://images.unsplash.com/photo-1537368910025-700350fe46c7?auto=format&fit=crop&w=300&q=80",
    },
  ]);

  const now = new Date();
  const doctorsResult = await mongoose.connection.collection("doctors").insertMany([
    {
      user: doctorUser._id,
      doctorName: "Dr. Mason Lee",
      specialization: "Cardiology",
      qualifications: "MBBS, MD Cardiology",
      experience: 13,
      consultationFee: 120,
      hospital: "Northline Heart Institute",
      image:
        "https://images.unsplash.com/photo-1537368910025-700350fe46c7?auto=format&fit=crop&w=600&q=80",
      days: ["Monday", "Wednesday", "Friday"],
      slots: ["09:00 AM", "11:30 AM", "03:00 PM"],
      verificationStatus: "verified",
      bio: "Focused on preventive heart care and rapid post-procedure recovery.",
      location: "New York, NY",
      ratingAverage: 0,
      reviewCount: 0,
      createdAt: now,
      updatedAt: now,
    },
    {
      doctorName: "Dr. Selina Ahmed",
      specialization: "Neurology",
      qualifications: "MBBS, FCPS Neurology",
      experience: 9,
      consultationFee: 95,
      hospital: "Cedar Neuro Center",
      image:
        "https://images.unsplash.com/photo-1559839734-2b71ea197ec2?auto=format&fit=crop&w=600&q=80",
      days: ["Sunday", "Tuesday", "Thursday"],
      slots: ["10:00 AM", "01:00 PM", "05:00 PM"],
      verificationStatus: "verified",
      bio: "Specializes in migraine care, memory clinics, and neuro-rehab planning.",
      location: "Austin, TX",
      ratingAverage: 0,
      reviewCount: 0,
      createdAt: now,
      updatedAt: now,
    },
    {
      doctorName: "Dr. Noor Patel",
      specialization: "Pediatrics",
      qualifications: "MBBS, DCH",
      experience: 7,
      consultationFee: 70,
      hospital: "Little Oaks Children's Hospital",
      image:
        "https://images.unsplash.com/photo-1594824476967-48c8b964273f?auto=format&fit=crop&w=600&q=80",
      days: ["Monday", "Tuesday", "Saturday"],
      slots: ["09:30 AM", "12:00 PM", "04:30 PM"],
      verificationStatus: "verified",
      bio: "Gentle pediatric care with a practical approach for busy families.",
      location: "Seattle, WA",
      ratingAverage: 0,
      reviewCount: 0,
      createdAt: now,
      updatedAt: now,
    },
  ]);

  const doctorIds = Object.values(doctorsResult.insertedIds);
  const primaryDoctorId = doctorIds[0];

  const appointment = await Appointment.create({
    patient: patient._id,
    doctor: primaryDoctorId,
    date: new Date(Date.now() + 86400000),
    time: "11:30 AM",
    symptoms: "Chest tightness during morning runs",
    status: "accepted",
    paymentStatus: "paid",
    amount: 120,
  });

  await Review.create([
    {
      patient: patient._id,
      doctor: primaryDoctorId,
      rating: 5,
      comment:
        "The booking was fast, the doctor had my notes ready, and the follow-up plan was clear.",
    },
    {
      patient: patient._id,
      doctor: doctorIds[1],
      rating: 5,
      comment:
        "MediCare Connect made it easy to compare specialists and avoid waiting-room delays.",
    },
    {
      patient: patient._id,
      doctor: doctorIds[2],
      rating: 4,
      comment: "The pediatric appointment reminders helped our family stay on schedule.",
    },
  ]);

  await Promise.all(doctorIds.map(recalculateDoctorRating));

  await Payment.create({
    appointment: appointment._id,
    patient: patient._id,
    doctor: primaryDoctorId,
    amount: appointment.amount,
    currency: "usd",
    transactionId: "demo_txn_heart_001",
    provider: "demo",
    status: "paid",
    paidAt: new Date(),
  });

  await Prescription.create({
    appointment: appointment._id,
    patient: patient._id,
    doctor: primaryDoctorId,
    diagnosis: "Exercise-induced angina observation",
    medications: [
      {
        name: "Aspirin",
        dosage: "75mg",
        duration: "14 days",
        instructions: "Take once daily after food.",
      },
    ],
    notes: "Schedule ECG and avoid high-intensity exercise until follow-up.",
  });

  console.log(
    `Seeded demo data. Admin: ${admin.email} / ${
      process.env.ADMIN_PASSWORD || "Admin#12345"
    }`,
  );
};

const connectDB = async () => {
  const mongoUri = process.env.MONGO_DB_URI;
  if (!mongoUri) throw new Error("Missing environment variable: MONGO_DB_URI");

  await mongoose.connect(mongoUri, { dbName: "medicare_connect" });
  await seedDemoData();
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
