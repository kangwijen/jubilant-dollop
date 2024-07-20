import express from 'express';
import sqlite3 from 'sqlite3';
import bcrypt from 'bcrypt';
import path from 'path';
import { fileURLToPath } from 'url';
import cookieParser from 'cookie-parser';
import crypto from 'crypto';

const app = express();
const port = 3000;
const hostname = '127.0.0.1';
const db = new sqlite3.Database('./js.db');
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const sessions = new Map();

db.serialize(() => {
  db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT, isAdmin INTEGER)");
});

function merge(target, source) {
  for (let key in source) {
    if (typeof source[key] === 'object' && source[key] !== null) {
      if (!target[key]) target[key] = {};
      merge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.listen(port, hostname, () => {
  console.log(`Server is running on http://${hostname}:${port}`);
});

app.get('/', (req, res) => {
  res.redirect('/login');
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'js_templates', 'login.html'));
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
    if (err) {
      return res.status(500).json({ success: false, message: 'Internal server error' });
    }
    if (user && bcrypt.compareSync(password, user.password)) {
      const sessionData = merge({}, { username: user.username, isAdmin: user.isAdmin === 1 });
      const sessionId = crypto.randomBytes(16).toString('hex');
      sessions.set(sessionId, { username: user.username });
      res.cookie('sessionId', sessionId, { httpOnly: false });
      res.json({ success: true, message: 'Logged in successfully', username: user.username });
    } else {
      res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
  });
});


app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'js_templates', 'register.html'));
});

app.post('/register', (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = bcrypt.hashSync(password, 10);
  if (!username || !password) {
    return res.status(400).json({ success: false, message: 'Username and password are required' });
  }

  if (username.toLowerCase() === 'admin') {
    return res.status(400).json({ success: false, message: 'Username is not allowed' });
  }

  db.run("INSERT INTO users (username, password, isAdmin) VALUES (?, ?, 0)", [username, hashedPassword], (err) => {
    if (err && err.errno === 19) {
      return res.status(400).json({ success: false, message: 'Username already exists' });
    }
    if (err) {
      return res.status(500).json({ success: false, message: 'Internal server error' });
    }
    res.json({ success: true, message: 'User registered successfully' });
  });
});

app.get('/admin', (req, res) => {
  const { sessionId } = req.cookies;
  const sessionData = sessions.get(sessionId);
  if (!sessionData) {
    return res.redirect('/login');  
  }
  
  if (req.query.isAdmin === 'true' || sessionData.isAdmin) {
    return res.sendFile('flag.txt', { root: __dirname });
  } else {
    return res.status(403).send('Access denied! Check /settings');
  }
});

app.get('/settings', (req, res) => {
  const { sessionId } = req.cookies;
  const sessionData = sessions.get(sessionId);
  if (!sessionData) {
    return res.redirect('/login');
  }

  res.sendFile(path.join(__dirname, 'js_templates', 'settings.html'));
});

app.post('/settings', (req, res) => {
  const { sessionId } = req.cookies;
  const sessionData = sessions.get(sessionId);

  if (!sessionData) {
    return res.status(401).json({ success: false, message: 'Unauthorized: Invalid session' });
  }

  const updatedSettings = merge({}, req.body);
  
  if (sessionData.username === updatedSettings.username) {
    if (updatedSettings.newPassword) {
      const hashedPassword = bcrypt.hashSync(updatedSettings.newPassword, 10);
      db.run("UPDATE users SET password = ? WHERE username = ?", [hashedPassword, sessionData.username], (err) => {
        if (err) {
          return res.status(500).json({ success: false, message: 'Internal server error' });
        }
        return res.json({ success: true, message: 'Password updated successfully' });
      });
    } else {
      return res.json({ success: false, message: 'No password update requested' });
    }
  } else {
    return res.status(401).json({ success: false, message: 'Unauthorized: Username mismatch' });
  }
});

app.get('/get-username', (req, res) => {
  const { sessionId } = req.cookies;
  const sessionData = sessions.get(sessionId);
  if (!sessionData) {
    return res.json({ success: false, message: 'Invalid session' });
  }
  res.json({ success: true, username: sessionData.username });
});