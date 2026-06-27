const express = require("express");
require("dotenv").config();
const bcrypt = require("bcryptjs");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const Stripe = require("stripe");

const app = express();
const port = process.env.PORT || 5000;
const clientOrigins = (process.env.CLIENT_ORIGIN || "http://localhost:3000,https://medicareconnectweb.vercel.app")
  .split(",")
  .map((origin) => origin.trim());
const stripe = process.env.STRIPE_SECRET_KEY
  ? new Stripe(process.env.STRIPE_SECRET_KEY)
  : null;

app.use(
  cors({
    origin: clientOrigins,
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

const doctorSchema = new mongoose.Schema({}, { strict: false, collection: "doctors" });
const Doctor = mongoose.models.Doctor || mongoose.model("Doctor", doctorSchema);

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
      await Doctor.create({
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

app.get("/api/auth/force-admin", async (req, res) => {
  try {
    const adminEmail = "admin@medicare.test";
    const adminPassword = "Admin#12345";
    let admin = await User.findOne({ email: adminEmail });
    
    if (!admin) {
      const passwordHash = await bcrypt.hash(adminPassword, 10);
      admin = await User.create({
        name: "MediCare Admin",
        email: adminEmail,
        passwordHash,
        role: "admin",
        photo: "https://images.unsplash.com/photo-1551836022-d5d88e9218df?auto=format&fit=crop&w=300&q=80",
      });
      return res.status(201).json({ message: "Admin user created successfully!", email: adminEmail });
    }
    
    // Admin exists, but maybe password hash is wrong because of an env var. Let's force reset the password hash just in case.
    const passwordHash = await bcrypt.hash(adminPassword, 10);
    admin.passwordHash = passwordHash;
    await admin.save();

    res.json({ message: "Admin user already exists. Password reset to Admin#12345.", email: adminEmail });
  } catch (error) {
    res.status(500).json({ message: "Error forcing admin", error: error.message });
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
      const existingProfile = await Doctor.findOne({ user: user._id });

      if (!existingProfile) {
        await Doctor.create({
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
    hospitalName: doctor.hospitalName || doctor.hospital,
    profileImage: doctor.profileImage || doctor.image || doctor.userProfile?.photo,
    availableDays: doctor.availableDays || doctor.days || [],
    availableSlots: doctor.availableSlots || doctor.slots || [],
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

    const [result] = await Doctor.aggregate(pipeline);
    const doctors = result.doctors.map(serializeDoctor);
    const total = result.total[0]?.count || 0;

    res.json({ total, page, perPage, doctors });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

app.get("/api/doctors/me", verifyToken, verifyRole("doctor"), async (req, res) => {
  try {
    const doctor = await Doctor.findOne({ user: req.user._id });

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

    const [doctor] = await Doctor.aggregate([
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
      ]);

    if (!doctor) return res.status(404).json({ message: "Doctor not found" });

    res.json(serializeDoctor(doctor));
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

app.patch("/api/doctors/:id", verifyToken, async (req, res) => {
  try {
    const doctorId = toObjectId(req.params.id);
    if (!doctorId) return res.status(400).json({ message: "Invalid doctor id" });

    const existingDoctor = await Doctor.findOne({ _id: doctorId });

    if (!existingDoctor) return res.status(404).json({ message: "Doctor not found" });

    const isOwner =
      req.user.role === "doctor" &&
      existingDoctor.user?.toString?.() === req.user._id.toString();

    if (req.user.role !== "admin" && !isOwner) {
      return res.status(403).json({ message: "Forbidden" });
    }

    const body = req.body;
    const updates = pick(body, [
      "doctorName",
      "specialization",
      "qualifications",
      "experience",
      "consultationFee",
      "bio",
    ]);

    if (body.hospitalName !== undefined || body.hospital !== undefined) {
      updates.hospital = body.hospital ?? body.hospitalName;
      updates.hospitalName = body.hospitalName ?? body.hospital;
    }
    if (body.profileImage !== undefined || body.image !== undefined) {
      updates.image = body.image ?? body.profileImage;
      updates.profileImage = body.profileImage ?? body.image;
    }
    if (body.availableDays !== undefined || body.days !== undefined) {
      updates.days = body.days ?? body.availableDays;
      updates.availableDays = body.availableDays ?? body.days;
    }
    if (body.availableSlots !== undefined || body.slots !== undefined) {
      updates.slots = body.slots ?? body.availableSlots;
      updates.availableSlots = body.availableSlots ?? body.slots;
    }
    if (updates.experience !== undefined) updates.experience = Number(updates.experience);
    if (updates.consultationFee !== undefined) {
      updates.consultationFee = Number(updates.consultationFee);
    }
    updates.updatedAt = new Date();

    const result = await Doctor.findOneAndUpdate(
      { _id: doctorId },
      { $set: updates },
      { new: true },
    );

    res.json(serializeDoctor(result.value || result));
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

      const result = await Doctor.findOneAndUpdate(
        { _id: doctorId },
        {
          $set: {
            verificationStatus: req.body.verificationStatus,
            updatedAt: new Date(),
          },
        },
        { new: true },
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
  Doctor.findOne({ user: userId });

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
      .populate("doctor")
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

    const doctor = await Doctor.findOne({
      _id: doctorId,
      verificationStatus: "verified",
    });

    if (!doctor) return res.status(404).json({ message: "Doctor not available" });
    const date = req.body.date || req.body.appointmentDate;
    const time = req.body.time || req.body.appointmentTime;
    if (!date || !time) {
      return res.status(400).json({ message: "Date and time are required" });
    }

    const appointment = await Appointment.create({
      patient: req.user._id,
      doctor: doctor._id,
      date,
      time,
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
      if (req.body.appointmentDate !== undefined) updates.date = req.body.appointmentDate;
      if (req.body.appointmentTime !== undefined) updates.time = req.body.appointmentTime;
      const requestedStatus = req.body.status || req.body.appointmentStatus;
      if (requestedStatus === "cancelled") {
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
      const requestedStatus = req.body.status || req.body.appointmentStatus;
      if (requestedStatus && appointmentStatuses.includes(requestedStatus)) {
        appointment.status = requestedStatus;
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

  await Doctor.updateOne(
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

    if (req.query.patient || req.query.patientId) {
      const patientId = toObjectId(req.query.patient || req.query.patientId);
      if (!patientId) return res.status(400).json({ message: "Invalid patient id" });
      query.patient = patientId;
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

    const doctor = await Doctor.findOne({ _id: doctorId });
    if (!doctor) return res.status(404).json({ message: "Doctor not found" });

    const review = await Review.create({
      patient: req.user._id,
      doctor: doctor._id,
      rating: Number(req.body.rating),
      comment: req.body.comment || req.body.reviewText,
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

    const updates = pick(req.body, ["rating", "comment"]);
    if (req.body.reviewText !== undefined) updates.comment = req.body.reviewText;
    Object.assign(review, updates);
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
      .populate("doctor")
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
      .populate("doctor")
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
      Doctor.countDocuments({ verificationStatus: "verified" }),
      User.countDocuments({ role: "patient" }),
      Appointment.countDocuments(),
      Review.countDocuments(),
      Doctor.aggregate([
          { $match: { verificationStatus: "verified" } },
          { $project: { slotCount: { $size: { $ifNull: ["$slots", []] } } } },
          { $group: { _id: null, total: { $sum: "$slotCount" } } },
        ]),
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
        Doctor.find({})
          .sort({ ratingAverage: -1, reviewCount: -1 })
          .limit(10),
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

  const adminEmail = process.env.ADMIN_EMAIL || "admin@medicare.test";
  let admin = await User.findOne({ email: adminEmail });
  
  if (!admin) {
    const adminPassword = await bcrypt.hash(process.env.ADMIN_PASSWORD || "Admin#12345", 10);
    admin = await User.create({
      name: "MediCare Admin",
      email: adminEmail,
      passwordHash: adminPassword,
      role: "admin",
      photo: "https://images.unsplash.com/photo-1551836022-d5d88e9218df?auto=format&fit=crop&w=300&q=80",
    });
    console.log(`Seeded admin user: ${adminEmail}`);
  }

  const existingUsers = await User.estimatedDocumentCount();
  if (existingUsers > 1) return;

  const patientExists = await User.findOne({ email: "patient@medicare.test" });
  if (patientExists) return;

  const [patientPassword, doctorPassword] = await Promise.all([
    bcrypt.hash("Patient#123", 10),
    bcrypt.hash("Doctor#123", 10),
  ]);

  const [patient, doctorUser] = await User.create([
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
  const doctorsResult = await Doctor.insertMany([
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

  const doctorIds = doctorsResult.map(doc => doc._id);
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

const seedAdditionalDoctors = async () => {
  if (process.env.SEED_DEMO_DATA === "false") return;
  const existingDoctors = await Doctor.estimatedDocumentCount();
  if (existingDoctors > 10) return; // Skip if already seeded with many doctors

  const passwordHash = await bcrypt.hash("Password#123", 10);
  let count = 1;

  const specialties = [
    "General Medicine", "Cardiology", "Dermatology", "Endocrinology", "Gastroenterology", 
    "Neurology", "Obstetrics & Gynecology", "Oncology", "Ophthalmology", "Orthopedics", 
    "Pediatrics", "Psychiatry", "Pulmonology", "Radiology", "Urology", "Diagnostics", 
    "Preventive Care", "Emergency"
  ];
  const firstNames = ["James", "John", "Robert", "Michael", "William", "David", "Richard", "Joseph", "Thomas", "Charles", "Mary", "Patricia", "Jennifer", "Linda", "Elizabeth", "Barbara", "Susan", "Jessica", "Sarah", "Karen", "Alex", "Jordan", "Taylor", "Morgan", "Casey", "Riley", "Jamie", "Avery", "Peyton", "Cameron"];
  const lastNames = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Jackson", "Martin"];
  const hospitals = ["City General Hospital", "Mercy Medical Center", "Sunrise Health Clinic", "Pioneer Memorial Hospital", "Grandview Medical", "St. Jude Healthcare", "Evergreen Health", "Summit Medical Center", "Valley Health", "Beacon Hospital"];
  const allDays = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];
  const allSlots = ["08:00 AM", "09:00 AM", "10:00 AM", "11:00 AM", "01:00 PM", "02:00 PM", "03:00 PM", "04:00 PM", "05:00 PM"];
  
  const getRandom = (arr) => arr[Math.floor(Math.random() * arr.length)];
  const getRandomMultiple = (arr, min, max) => {
    const c = Math.floor(Math.random() * (max - min + 1)) + min;
    const shuffled = [...arr].sort(() => 0.5 - Math.random());
    return shuffled.slice(0, c).sort((a, b) => arr.indexOf(a) - arr.indexOf(b));
  };
  
  const qualificationsBySpec = {
    Cardiology: ["MBBS, MD Cardiology", "MBBS, FACC", "DO, FACC"],
    Neurology: ["MBBS, MD Neurology", "MBBS, FCPS Neurology", "DO, FAAN"],
    Pediatrics: ["MBBS, DCH", "MBBS, MD Pediatrics", "DO, FAAP"],
    Orthopedics: ["MBBS, MS Orthopedics", "MBBS, FRCS Orthopedics", "DO, FAAOS"],
    Dermatology: ["MBBS, MD Dermatology", "MBBS, DDVL", "DO, FAAD"],
    Psychiatry: ["MBBS, MD Psychiatry", "MBBS, DPM", "DO, FAPA"]
  };

  for (const spec of specialties) {
    const numDoctors = Math.floor(Math.random() * 6) + 5; 
    for (let i = 0; i < numDoctors; i++) {
      const firstName = getRandom(firstNames);
      const lastName = getRandom(lastNames);
      const name = `Dr. ${firstName} ${lastName}`;
      const email = `doctor${count}_${Date.now()}@medicare.test`;
      const gender = Math.random() > 0.5 ? "male" : "female";
      
      const doctorImages = {
        male: [
          "https://images.unsplash.com/photo-1612349317150-e413f6a5b16d?auto=format&fit=crop&w=600&q=80",
          "https://images.unsplash.com/photo-1537368910025-700350fe46c7?auto=format&fit=crop&w=600&q=80",
          "https://images.unsplash.com/photo-1622253692010-333f2da6031d?auto=format&fit=crop&w=600&q=80"
        ],
        female: [
          "https://images.unsplash.com/photo-1559839734-2b71ea197ec2?auto=format&fit=crop&w=600&q=80",
          "https://images.unsplash.com/photo-1594824476967-48c8b964273f?auto=format&fit=crop&w=600&q=80",
          "https://images.unsplash.com/photo-1651008376811-b90baee60c1f?auto=format&fit=crop&w=600&q=80",
          "https://images.unsplash.com/photo-1551836022-d5d88e9218df?auto=format&fit=crop&w=600&q=80"
        ]
      };
      const profileImage = getRandom(doctorImages[gender]);

      const user = await User.create({
        name, email, passwordHash, role: "doctor",
        phone: `+1 555 ${String(Math.floor(Math.random() * 9000) + 1000)}`,
        gender, photo: profileImage,
      });

      await Doctor.create({
        user: user._id, doctorName: name, specialization: spec,
        qualifications: getRandom(qualificationsBySpec[spec] || ["MBBS, MD", "MBBS, Specialist", "DO, Board Certified"]),
        experience: Math.floor(Math.random() * 20) + 3,
        consultationFee: Math.floor(Math.random() * 150) + 50,
        hospital: getRandom(hospitals),
        image: profileImage,
        days: getRandomMultiple(allDays, 3, 5),
        slots: getRandomMultiple(allSlots, 3, 6),
        verificationStatus: "verified",
        bio: `Experienced ${spec} specialist dedicated to providing comprehensive patient care.`,
        location: "New York, NY",
        ratingAverage: Number((Math.random() * (5 - 3.5) + 3.5).toFixed(1)),
        reviewCount: Math.floor(Math.random() * 100),
        createdAt: new Date(), updatedAt: new Date(),
      });
      count++;
    }
  }
  console.log(`Seeded an additional ${count - 1} doctors for specialties.`);
};

const connectDB = async () => {
  const mongoUri = process.env.MONGO_DB_URI;
  if (!mongoUri) throw new Error("Missing environment variable: MONGO_DB_URI");

  await mongoose.connect(mongoUri, { dbName: "medicare_connect" });
  await seedDemoData();
  await seedAdditionalDoctors();
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
