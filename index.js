const express = require("express");

const app = express();
const port = process.env.PORT || 5000;

app.use(express.json());

app.get("/", (_req, res) => {
  res.send("MediCare Connect API is healthy");
});

app.listen(port, () => {
  console.log(`MediCare Connect API running on http://localhost:${port}`);
});

module.exports = app;
