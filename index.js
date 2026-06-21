const express = require("express");
require("dotenv").config();
const cors = require("cors");

const app = express();
const port = process.env.PORT || 5000;

app.use(
  cors({
    origin: process.env.CLIENT_ORIGIN?.split(",") || "*",
    credentials: true,
  }),
);
app.use(express.json());

app.get("/", (_req, res) => {
  res.send("MediCare Connect API is healthy");
});

app.listen(port, () => {
  console.log(`MediCare Connect API running on http://localhost:${port}`);
});

module.exports = app;
