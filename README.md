# MediCare Connect Server

A robust Express.js backend for the MediCare Connect application. This server handles role-based authentication, doctor management, appointment booking, reviews, prescriptions, Stripe payments, and healthcare analytics, backed by MongoDB.

🔗 **Live Client Application**: [https://medicareconnectweb.vercel.app/](https://medicareconnectweb.vercel.app/)

## 🚀 Features

- **Doctor Management**: Add, update, verify, list, and search doctor profiles.
- **Appointment System**: Patients can book appointments, doctors can manage appointment status, and users can reschedule or cancel appointments based on role permissions.
- **Authentication & Authorization**: JWT-based authentication with patient, doctor, and admin role protection.
- **Payments**: Stripe checkout session support with a demo fallback when Stripe is not configured.
- **Prescriptions**: Doctors and admins can create and update prescriptions linked to completed appointments.
- **Reviews & Ratings**: Patients can review doctors, and doctor rating averages are recalculated automatically.
- **Analytics & Statistics**: Public stats and protected admin analytics for doctors, patients, appointments, revenue, and activity trends.
- **Search & Filtering**: Search doctors by name or specialization, filter by verification status, paginate results, and sort by fee, experience, or rating.
- **CORS Configured**: Ready to integrate with the deployed frontend and local development clients.

## 🛠️ Tech Stack

- **Runtime**: Node.js
- **Framework**: Express.js
- **Database**: MongoDB with Mongoose
- **Authentication**: JWT using `jsonwebtoken` and password hashing with `bcryptjs`
- **Payments**: Stripe
- **Environment Management**: `dotenv`
- **Development Tooling**: Node watch mode

## 📋 Prerequisites

Before you begin, ensure you have the following installed:

- [Node.js](https://nodejs.org/) (current LTS recommended)
- [MongoDB](https://www.mongodb.com/try/download/community) or a MongoDB Atlas connection URI
- A [Stripe](https://stripe.com/) secret key if you want live payment checkout

## ⚙️ Installation & Setup

1. **Clone the repository:**

   ```bash
   git clone <repository-url>
   cd MediCare-Connect-Server
   ```

2. **Install dependencies:**

   ```bash
   npm install
   ```

3. **Configure Environment Variables:**
   Create a `.env` file in the root directory based on your environment:

   ```env
   PORT=5000
   CLIENT_ORIGIN=http://localhost:3000,https://medicareconnectweb.vercel.app
   MONGO_DB_URI=your_mongodb_connection_string
   JWT_SECRET=your_jwt_secret_key
   JWT_EXPIRES_IN=7d
   STRIPE_SECRET_KEY=sk_test_your_stripe_secret_key
   ```

4. **Start the server:**

   To run in development mode with Node watch mode:

   ```bash
   npm run dev
   ```

   To run normally:

   ```bash
   npm start
   ```

5. **Check the server syntax:**
   ```bash
   npm test
   ```

## 📡 API Endpoints

### Public Routes

- `GET /` - Health check. Returns server status.
- `POST /api/auth/register` - Register a patient or doctor account.
- `POST /api/auth/login` - Log in with email and password.
- `POST /api/auth/google` - Log in or register with Google profile data.
- `GET /api/auth/force-admin` - Create or reset the demo admin user.
- `GET /api/doctors` - Fetch verified doctors.
  - **Query Params**: `search` (string), `specialization` (string), `status` (string), `includeUnverified` (boolean), `page` (number), `perPage` (number), `sort` (`fee_asc`, `fee_desc`, `experience`, `rating`).
- `GET /api/doctors/:id` - Fetch a specific doctor profile.
- `GET /api/reviews` - Fetch reviews.
  - **Query Params**: `doctor` / `doctorId`, `patient` / `patientId`.
- `GET /api/stats` - Fetch public platform statistics.

### Protected Routes (Requires JWT)

**Profile:**

- `GET /api/auth/me` - Get the authenticated user profile.
- `PATCH /api/users/me` - Update the authenticated user profile.

**Users (Admin):**

- `GET /api/users` - Fetch all users.
- `PATCH /api/users/:id` - Update a user.
- `PATCH /api/users/:id/status` - Update a user's account status.
- `DELETE /api/users/:id` - Delete a user.

**Doctors:**

- `GET /api/doctors/me` - Get the authenticated doctor's profile.
- `PATCH /api/doctors/:id` - Update a doctor profile as the owner doctor or admin.
- `PATCH /api/doctors/:id/verification` - Update doctor verification status as an admin.

**Appointments:**

- `GET /api/appointments` - Fetch appointments scoped to the authenticated user role.
- `POST /api/appointments` - Book an appointment as a patient.
- `PATCH /api/appointments/:id` - Update, reschedule, cancel, or change appointment status.

**Reviews:**

- `POST /api/reviews` - Add a doctor review as a patient.
- `PATCH /api/reviews/:id` - Update a review as the owner patient or admin.
- `DELETE /api/reviews/:id` - Delete a review as the owner patient or admin.

**Payments:**

- `GET /api/payments` - Fetch payments scoped to the authenticated user role.
- `POST /api/payments/create-intent` - Create a Stripe checkout session or demo payment response.
- `POST /api/payments` - Record a payment.

**Prescriptions:**

- `GET /api/prescriptions` - Fetch prescriptions scoped to the authenticated user role.
- `POST /api/prescriptions` - Create a prescription as a doctor or admin.
- `PATCH /api/prescriptions/:id` - Update a prescription as the owner doctor or admin.

**Analytics (Admin):**

- `GET /api/analytics` - Fetch admin analytics and dashboard data.

## 🔒 Authentication

This API uses JSON Web Tokens (JWT) for securing protected routes. You must include the token in the `Authorization` header of your HTTP requests:

```http
Authorization: Bearer <your_jwt_token>
```

## 🔗 Project Links

**Client Repo:** [https://github.com/smRid/PHA10-MediCare-Connect](https://github.com/smRid/PHA10-MediCare-Connect)

**Live Frontend:** [https://medicareconnectweb.vercel.app/](https://medicareconnectweb.vercel.app/)

**Live API:** [https://medicareconnectwebserver.vercel.app/](https://medicareconnectwebserver.vercel.app/)
