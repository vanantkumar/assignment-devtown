const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");

const app = express();
app.use(bodyParser.json());

// In-memory "database" (use MongoDB/Postgres in real apps)
const users = [];

// Secret key for JWT (store in env variable in production!)
const JWT_SECRET = "mySuperSecretKey";

// ------------------ REGISTER ------------------
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  // check if user exists
  const existingUser = users.find(u => u.username === username);
  if (existingUser) return res.status(400).json({ error: "User already exists" });

  // hash password
  const hashedPassword = await bcrypt.hash(password, 10);

  // save user
  users.push({ username, password: hashedPassword });
  res.json({ message: "User registered successfully" });
});

// ------------------ LOGIN ------------------
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  // find user
  const user = users.find(u => u.username === username);
  if (!user) return res.status(400).json({ error: "Invalid credentials" });

  // verify password
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(400).json({ error: "Invalid credentials" });

  // create JWT
  const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: "1h" });
  res.json({ message: "Login successful", token });
});

// ------------------ PROTECTED ROUTE ------------------
app.get("/profile", authenticateToken, (req, res) => {
  res.json({ message: `Welcome ${req.user.username}! This is your profile.` });
});

// Middleware to verify JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Access denied" });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Invalid token" });
    req.user = user; // attach decoded payload
    next();
  });
}

// ------------------ START SERVER ------------------
app.listen(3000, () => console.log("Server running on http://localhost:3000"));
