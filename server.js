const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");

if (!process.env.JWT_SECRET) {
  console.error("JWT_SECRET .env файлд байхгүй байна");
  process.exit(1);
}

const app = express();
const loginLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 5,
  message: {
    error: "Хэт олон оролдлого. 1 минутын дараа дахин оролд"
  }
});
app.use(express.json());
app.use(express.static("public"));

const pool = mysql.createPool({
  host: "127.0.0.1",
  user: "root",
  password: "",
  database: "auth_db"
});

app.post("/api/register", async (req, res) => {
  try {
    const { email, password } = req.body || {};

    if (typeof email !== "string" || !email.includes("@")) {
      return res.status(400).json({
        error: "И-мэйл буруу байна"
      });
    }

    if (
      typeof password !== "string" ||
      password.length < 8 ||
      Buffer.byteLength(password) > 72
    ) {
      return res.status(400).json({
        error: "Нууц үг 8-аас доошгүй, 72 byte-аас ихгүй байна"
      });
    }

    const hash = await bcrypt.hash(password, 10);

    const [r] = await pool.query(
      "INSERT INTO users (email, password_hash) VALUES (?, ?)",
      [email.toLowerCase(), hash]
    );

    res.status(201).json({
      id: r.insertId,
      email: email.toLowerCase()
    });
  } catch (err) {
    if (err.code === "ER_DUP_ENTRY") {
      return res.status(409).json({
        error: "Энэ и-мэйл бүртгэлтэй байна"
      });
    }

    console.error(err);
    res.status(500).json({
      error: "Серверийн алдаа"
    });
  }
});

app.post("/api/login", loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body || {};

    if (
      typeof email !== "string" ||
      typeof password !== "string"
    ) {
      return res.status(400).json({
        error: "И-мэйл, нууц үг шаардлагатай"
      });
    }

    const [rows] = await pool.query(
      "SELECT id, email, password_hash, role FROM users WHERE email = ?",
      [email.toLowerCase()]
    );

    const user = rows[0];
    const ok =
      user && await bcrypt.compare(password, user.password_hash);

    if (!ok) {
      return res.status(401).json({
        error: "И-мэйл эсвэл нууц үг буруу"
      });
    }

    const token = jwt.sign(
      { userId: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "15m" }
    );

    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: "Серверийн алдаа"
    });
  }
});

function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  const token = auth && auth.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Токен алга" });
  }

  jwt.verify(
    token,
    process.env.JWT_SECRET,
    { algorithms: ["HS256"] },
    (err, payload) => {
      if (err) {
        return res.status(403).json({ error: "Хүчингүй токен" });
      }

      req.user = payload;
      next();
    }
  );
}

function requireRole(role) {
  return (req, res, next) => {
    if (req.user.role !== role) {
      return res.status(403).json({ error: "Эрх хүрэхгүй" });
    }

    next();
  };
}

app.get("/api/profile", requireAuth, async (req, res) => {
  try {
    const [rows] = await pool.query(
      "SELECT id, email, role, created_at FROM users WHERE id = ?",
      [req.user.userId]
    );

    if (!rows[0]) {
      return res.status(404).json({
        error: "Хэрэглэгч олдсонгүй"
      });
    }

    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Серверийн алдаа" });
  }
});

app.get(
  "/api/admin",
  requireAuth,
  requireRole("admin"),
  (req, res) => {
    res.json({
      message: "Админ хэсэг. Хэрэглэгч №" + req.user.userId
    });
  }
);

app.listen(3000, () => {
  console.log("http://localhost:3000");
});