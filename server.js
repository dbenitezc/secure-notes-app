const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const session = require('express-session');
const nodemailer = require('nodemailer');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(express.json());
app.use(cors());
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true
}));

// Rate limiter to prevent brute force attacks
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 login requests per windowMs
  message: 'Too many login attempts. Try again later.'
});

// Fake database
const users = [];

// Email Transporter for 2FA
const transporter = nodemailer.createTransport({
  service: 'Gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Register User
app.post('/register',
  body('email').isEmail(),
  body('password').isLength({ min: 6 }),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const user = { email, password: hashedPassword, twoFactorCode: null };
    users.push(user);
    res.status(201).json({ message: 'User registered successfully' });
  }
);

// Login with 2FA
app.post('/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email);

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  // Generate 2FA code
  const twoFactorCode = Math.floor(100000 + Math.random() * 900000).toString();
  user.twoFactorCode = twoFactorCode;

  console.log(`Generated 2FA Code for ${email}: ${twoFactorCode}`); // Debug log

  // Send email with the 2FA code
  await transporter.sendMail({
    to: email,
    subject: 'Your 2FA Code',
    text: `Your authentication code is: ${twoFactorCode}`
  });

  res.json({ message: '2FA code sent to email' });
});

// Verify 2FA
app.post('/verify-2fa', (req, res) => {
  const { email, code } = req.body;
  const user = users.find(u => u.email === email);

  console.log(`User email: ${email}`);
  console.log(`Received 2FA Code: ${code}`);
  console.log(`Stored 2FA Code: ${user ? user.twoFactorCode : "User not found"}`);

  if (!user || user.twoFactorCode !== code) {
    return res.status(401).json({ message: 'Invalid 2FA code' });
  }

  // Generate JWT
  const token = jwt.sign({ email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));


// Fake database for notes
const notes = [];

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
    const token = req.headers["authorization"];
    if (!token) return res.status(401).json({ message: "Access denied" });

    jwt.verify(token.split(" ")[1], process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: "Invalid token" });
        req.user = user;
        next();
    });
};

// Create a note
app.post("/notes", authenticateToken, (req, res) => {
    const { title, content } = req.body;
    const note = { id: notes.length + 1, email: req.user.email, title, content };
    notes.push(note);
    res.json({ message: "Note added successfully", note });
});

// Get all notes for the authenticated user
app.get("/notes", authenticateToken, (req, res) => {
    const userNotes = notes.filter(n => n.email === req.user.email);
    res.json(userNotes);
});

// Edit a note
app.put("/notes/:id", authenticateToken, (req, res) => {
    const { id } = req.params;
    const { title, content } = req.body;
    const note = notes.find(n => n.id == id && n.email === req.user.email);
    
    if (!note) return res.status(404).json({ message: "Note not found" });

    note.title = title;
    note.content = content;
    res.json({ message: "Note updated successfully", note });
});

// Delete a note
app.delete("/notes/:id", authenticateToken, (req, res) => {
    const index = notes.findIndex(n => n.id == req.params.id && n.email === req.user.email);
    
    if (index === -1) return res.status(404).json({ message: "Note not found" });

    notes.splice(index, 1);
    res.json({ message: "Note deleted successfully" });
});

