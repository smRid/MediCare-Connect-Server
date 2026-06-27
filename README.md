<div align="center">

# MediCare Connect Server

### The Backend API for MediCare Connect

This is the Express & MongoDB backend server that powers the MediCare Connect healthcare platform. It handles robust role-based authentication, real-time analytics aggregation, secure Stripe payments, and complex data models for Appointments, Prescriptions, Doctors, and Patients.

[![Node.js](https://img.shields.io/badge/Node.js-18-339933?style=for-the-badge&logo=node.js&logoColor=white)](https://nodejs.org/)
[![Express](https://img.shields.io/badge/Express-4-000000?style=for-the-badge&logo=express&logoColor=white)](https://expressjs.com/)
[![MongoDB](https://img.shields.io/badge/MongoDB-7-47A248?style=for-the-badge&logo=mongodb&logoColor=white)](https://www.mongodb.com/)
[![Deployed on Vercel](https://img.shields.io/badge/Vercel-Deployed-000?style=for-the-badge&logo=vercel&logoColor=white)](https://medicareconnectwebserver.vercel.app/)

</div>

---

## ?? Project Links
> **?? Client Repo:** [https://github.com/smRid/PHA10-MediCare-Connect](https://github.com/smRid/PHA10-MediCare-Connect)
> **?? Live Frontend:** [https://medicareconnectweb.vercel.app/](https://medicareconnectweb.vercel.app/)
> **?? Live API:** [https://medicareconnectwebserver.vercel.app/](https://medicareconnectwebserver.vercel.app/)

## ? Key Features
- **JWT & Role-based Auth:** Granular middleware controlling access for dmin, doctor, and patient roles.
- **Advanced Aggregation:** Complex MongoDB pipelines for charting real-time analytics and statistics.
- **Stripe Integration:** Server-side generation of secure checkout sessions and payment intents.
- **Dynamic Search & Filtering:** Paginated endpoints supporting multi-faceted doctor search.

## ?? Environment Variables

Create a .env file in the root of the server repository:

\\\env
# MongoDB Connection
MONGO_URI=your_mongodb_connection_string

# Authentication
JWT_SECRET=your_jwt_secret
JWT_EXPIRES_IN=7d

# Stripe
STRIPE_SECRET_KEY=sk_test_...

# Client URLs (CORS)
CLIENT_URL=http://localhost:3000
\\\

## ?? Quick Start

1. Install dependencies:
   \\\ash
   npm install
   \\\
2. Start the development server:
   \\\ash
   npm run dev
   \\\
3. The API will be available at \http://localhost:5000\ (or your configured port).

## ?? Deployment
This Express API is optimized for stateless deployment on **Vercel**. Ensure that CORS is configured to accept requests from your production frontend domain and that IP access limits in MongoDB Atlas allow connections from Vercel's IP addresses.
