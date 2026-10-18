require("dotenv").config();

const express = require("express");
const jwt = require("jsonwebtoken");

const app = express();
const port = Number(process.env.PORT) || 3000;
const jwtSecret = process.env.JWT_SECRET;

if (!jwtSecret) {
  throw new Error("Set JWT_SECRET in your .env file.");
}

app.use(express.json());

// Demo account for this assignment.
const users = [{ id: 1, username: "user1", password: "password123" }];

const movies = [
  { id: 1, title: "The Last Horizon", genre: "Adventure" },
  { id: 2, title: "Neon City", genre: "Science Fiction" },
  { id: 3, title: "The Hidden Kingdom", genre: "Fantasy" }
];

app.post("/login", (req, res) => {
  const { username, password } = req.body || {};
  const user = users.find((entry) =>
    entry.username === username && entry.password === password
  );

  if (!user) {
    return res.status(401).json({ message: "Invalid username or password" });
  }

  const token = jwt.sign(
    { id: user.id, username: user.username },
    jwtSecret,
    { algorithm: "HS256", expiresIn: "1h" }
  );

  return res.json({
    message: "Login successful",
    token
  });
});

function authenticateToken(req, res, next) {
  const authorization = req.headers.authorization;
  const [scheme, token] = authorization ? authorization.split(" ") : [];

  if (scheme !== "Bearer" || !token) {
    return res.status(401).json({ message: "Access token is required" });
  }

  jwt.verify(token, jwtSecret, { algorithms: ["HS256"] }, (error, payload) => {
    if (error) {
      return res.status(403).json({ message: "Invalid or expired token" });
    }
    req.user = payload;
    return next();
  });
}

app.get("/movies", authenticateToken, (_req, res) => {
  res.json({ movies });
});

app.use((_req, res) => {
  res.status(404).json({ message: "Route not found" });
});

app.listen(port, () => console.log(`Server listening on port ${port}`));
