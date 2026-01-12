// server.js
import express from "express";
import mysql from "mysql2/promise";
import bodyParser from "body-parser";
import bcrypt from "bcrypt";
import session from "express-session";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const port = 8082;

// Configure MySQL connection (ubah sesuai Laragon)
const dbConfig = {
  host: "localhost",
  user: "root",
  password: "",
  database: "kegiatankampusku",
  multipleStatements: false,
};

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
  secret: "kegiatan_kampusku_secret",
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000 } // 1 hari
}));

// Serve static files
app.use(express.static(path.join(__dirname, "public")));

// Helper: get DB connection
async function getDb() {
  return mysql.createConnection(dbConfig);
}

// Middleware auth check
function requireLogin(req, res, next) {
  if (req.session && req.session.user) next();
  else res.status(401).json({ success: false, message: "Unauthorized" });
}

function requireRole(role) {
  return (req, res, next) => {
    if (req.session && req.session.user && req.session.user.role === role) next();
    else res.status(403).json({ success: false, message: "Forbidden" });
  }
}

/* ===== AUTH ===== */

// Register
app.post("/register", async (req, res) => {
  const { username, email, password, role } = req.body;
  if (!username || !email || !password || !role) {
    return res.status(400).json({ success: false, message: "Semua field wajib diisi" });
  }
  try {
    const conn = await getDb();
    const [exists] = await conn.execute("SELECT id FROM users WHERE email = ?", [email]);
    if (exists.length) {
      await conn.end();
      return res.status(400).json({ success: false, message: "Email sudah terdaftar" });
    }
    const hash = await bcrypt.hash(password, 10);
    await conn.execute(
      "INSERT INTO users (username,email,password,role) VALUES (?,?,?,?)",
      [username, email, hash, role]
    );
    await conn.end();
    res.json({ success: true, message: "Register berhasil. Silakan login." });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Login
app.post("/login", async (req, res) => {
  const { username, password } = req.body; // username = username or email (we use username)
  if (!username || !password) return res.status(400).json({ success: false, message: "Masukkan username & password" });
  try {
    const conn = await getDb();
    const [rows] = await conn.execute("SELECT * FROM users WHERE username = ?", [username]);
    await conn.end();
    if (!rows.length) return res.status(400).json({ success: false, message: "User tidak ditemukan" });
    const user = rows[0];
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ success: false, message: "Password salah" });

    // set session (tidak menyimpan password)
    req.session.user = { id: user.id, username: user.username, email: user.email, role: user.role };
    res.json({ success: true, message: "Login sukses", user: req.session.user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Logout
app.post("/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true, message: "Logout sukses" });
  });
});

/* ===== KEGIATAN (Admin) ===== */

// Get all kegiatan
app.get("/kegiatan", async (req, res) => {
  try {
    const conn = await getDb();
    const [rows] = await conn.execute("SELECT * FROM kegiatan ORDER BY tanggal_mulai DESC");
    await conn.end();
    res.json({ success: true, kegiatan: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Create kegiatan (admin)
app.post("/kegiatan", requireLogin, requireRole("admin"), async (req, res) => {
  const { nama_kegiatan, deskripsi, tanggal_mulai, tanggal_akhir } = req.body;
  if (!nama_kegiatan || !tanggal_mulai || !tanggal_akhir) {
    return res.status(400).json({ success: false, message: "Lengkapi data kegiatan" });
  }
  try {
    const conn = await getDb();
    await conn.execute(
      "INSERT INTO kegiatan (nama_kegiatan, deskripsi, tanggal_mulai, tanggal_akhir) VALUES (?,?,?,?)",
      [nama_kegiatan, deskripsi || "", tanggal_mulai, tanggal_akhir]
    );
    await conn.end();
    res.json({ success: true, message: "Kegiatan dibuat" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Update kegiatan (admin)
app.put("/kegiatan/:id", requireLogin, requireRole("admin"), async (req, res) => {
  const id = req.params.id;
  const { nama_kegiatan, deskripsi, tanggal_mulai, tanggal_akhir } = req.body;
  try {
    const conn = await getDb();
    await conn.execute(
      "UPDATE kegiatan SET nama_kegiatan=?, deskripsi=?, tanggal_mulai=?, tanggal_akhir=? WHERE id=?",
      [nama_kegiatan, deskripsi, tanggal_mulai, tanggal_akhir, id]
    );
    await conn.end();
    res.json({ success: true, message: "Kegiatan diperbarui" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Delete kegiatan (admin)
app.delete("/kegiatan/:id", requireLogin, requireRole("admin"), async (req, res) => {
  const id = req.params.id;
  try {
    const conn = await getDb();
    await conn.execute("DELETE FROM kegiatan WHERE id = ?", [id]);
    await conn.end();
    res.json({ success: true, message: "Kegiatan dihapus" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

/* ===== PENDAFTARAN ===== */

// Mahasiswa daftar kegiatan
app.post("/daftar", requireLogin, async (req, res) => {
  // Only mahasiswa can register for kegiatan (admin cannot)
  if (req.session.user.role !== "mahasiswa") {
    return res.status(403).json({ success: false, message: "Hanya mahasiswa yang dapat mendaftar" });
  }
  const { kegiatan_id, nim, prodi } = req.body;
  if (!kegiatan_id || !nim || !prodi) return res.status(400).json({ success: false, message: "Lengkapi data pendaftaran" });

  try {
    const conn = await getDb();
    // Check kegiatan exists & deadline
    const [kegRows] = await conn.execute("SELECT * FROM kegiatan WHERE id = ?", [kegiatan_id]);
    if (!kegRows.length) {
      await conn.end();
      return res.status(400).json({ success: false, message: "Kegiatan tidak ditemukan" });
    }
    const kegiatan = kegRows[0];
    const now = new Date();
    const deadline = new Date(kegiatan.tanggal_akhir);
    if (now > deadline) {
      await conn.end();
      return res.status(400).json({ success: false, message: "Pendaftaran sudah ditutup (deadline terlewati)" });
    }

    // Check duplicate registration by same user for same kegiatan
    const [dup] = await conn.execute(
      "SELECT id FROM pendaftaran WHERE user_id = ? AND kegiatan_id = ?",
      [req.session.user.id, kegiatan_id]
    );
    if (dup.length) {
      await conn.end();
      return res.status(400).json({ success: false, message: "Sudah mendaftar kegiatan ini" });
    }

    // Insert pendaftaran
    await conn.execute(
      "INSERT INTO pendaftaran (user_id, nama, nim, prodi, email, kegiatan_id) VALUES (?,?,?,?,?,?)",
      [req.session.user.id, req.session.user.username, nim, prodi, req.session.user.email, kegiatan_id]
    );
    await conn.end();
    res.json({ success: true, message: "Pendaftaran berhasil" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Get pendaftaran for admin (lihat semua pendaftar atau filter by kegiatan)
app.get("/pendaftaran/admin", requireLogin, requireRole("admin"), async (req, res) => {
  const kegiatanId = req.query.kegiatan_id || null;
  try {
    const conn = await getDb();
    let sql = `SELECT p.id, p.nama, p.nim, p.prodi, p.email, k.nama_kegiatan, p.tanggal_daftar
               FROM pendaftaran p
               JOIN kegiatan k ON p.kegiatan_id = k.id`;
    const params = [];
    if (kegiatanId) {
      sql += " WHERE p.kegiatan_id = ?";
      params.push(kegiatanId);
    }
    sql += " ORDER BY p.tanggal_daftar DESC";
    const [rows] = await conn.execute(sql, params);
    await conn.end();
    res.json({ success: true, pendaftar: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Get pendaftaran for mahasiswa (riwayat)
app.get("/pendaftaran/mahasiswa", requireLogin, requireRole("mahasiswa"), async (req, res) => {
  try {
    const conn = await getDb();
    const [rows] = await conn.execute(
      `SELECT p.id, p.nama, p.nim, p.prodi, k.nama_kegiatan, p.tanggal_daftar
       FROM pendaftaran p
       JOIN kegiatan k ON p.kegiatan_id = k.id
       WHERE p.user_id = ? ORDER BY p.tanggal_daftar DESC`,
      [req.session.user.id]
    );
    await conn.end();
    res.json({ success: true, daftar: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

/* ===== Server Start ===== */
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(port, () => {
  console.log(`Server berjalan di http://localhost:${port}`);
});

