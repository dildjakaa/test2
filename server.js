const http = require('http');
const WebSocket = require('ws');
const mongoose = require('mongoose');
const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Message = require('./Message');
const User = require('./User');

dotenv.config({ path: path.resolve(__dirname, '.env') });

const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret';

if (!MONGO_URI) {
  console.error('❌ Переменная окружения MONGO_URI не задана. Добавьте ее в .env');
  process.exit(1);
}

mongoose
  .connect(MONGO_URI, {
    serverSelectionTimeoutMS: 15000,
    socketTimeoutMS: 60000,
    maxPoolSize: 5,
  })
  .then(() => console.log('✅ Подключено к MongoDB'))
  .catch((err) => {
    console.error('❌ Ошибка подключения к MongoDB:', err);
    process.exit(1);
  });

// HTTP server (Express)
const app = express();
app.use(cors());
app.use(express.json());

// Lightweight health check to help with warmups
app.get('/api/health', (_req, res) => {
  res.json({ ok: true, uptime: process.uptime() });
});

// Auth: Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) {
      return res.status(400).json({ error: 'username and password are required' });
    }
    const usernameLower = String(username).trim().toLowerCase();
    const existing = await User.findOne({ usernameLower });
    if (existing) {
      return res.status(409).json({ error: 'username already taken' });
    }
    const passwordHash = await bcrypt.hash(password, 10);
    const user = await User.create({ username: String(username).trim(), usernameLower, passwordHash });
    return res.status(201).json({ id: user._id, username: user.username, createdAt: user.createdAt });
  } catch (e) {
    console.error('Register error:', e);
    return res.status(500).json({ error: 'internal_error' });
  }
});

// Auth: Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) {
      return res.status(400).json({ error: 'username and password are required' });
    }
    const usernameLower = String(username).trim().toLowerCase();
    const user = await User.findOne({ usernameLower });
    if (!user) {
      return res.status(401).json({ error: 'invalid_credentials' });
    }
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) {
      return res.status(401).json({ error: 'invalid_credentials' });
    }
    const token = jwt.sign({ sub: String(user._id) }, JWT_SECRET, { expiresIn: '7d' });
    return res.json({ token, user: { id: user._id, username: user.username } });
  } catch (e) {
    console.error('Login error:', e);
    return res.status(500).json({ error: 'internal_error' });
  }
});

// Users list (public)
app.get('/api/users', async (_req, res) => {
  try {
    const users = await User.find({}, { username: 1 }).sort({ usernameLower: 1 }).lean();
    return res.json(users.map((u) => ({ id: u._id, username: u.username })));
  } catch (e) {
    console.error('Users list error:', e);
    return res.status(500).json({ error: 'internal_error' });
  }
});

const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

wss.on('connection', async (ws) => {
  console.log('🔌 Новый клиент подключился');

  try {
    // Последние 50 сообщений, по возрастанию времени
    const history = await Message.find()
      .sort({ timestamp: -1 })
      .limit(50)
      .lean();
    ws.send(
      JSON.stringify({ type: 'history', messages: history.reverse() })
    );
  } catch (e) {
    console.error('⚠️ Ошибка загрузки истории:', e);
  }

  ws.on('message', async (data) => {
    try {
      const text = typeof data === 'string' ? data : data.toString();
      const parsed = JSON.parse(text); // { username, text }

      if (!parsed?.username || !parsed?.text) return;

      const msg = await Message.create({
        username: parsed.username,
        text: parsed.text,
      });

      const outgoing = JSON.stringify({ type: 'message', message: msg });
      wss.clients.forEach((client) => {
        if (client.readyState === WebSocket.OPEN) {
          client.send(outgoing);
        }
      });
    } catch (err) {
      console.error('⚠️ Ошибка обработки сообщения:', err);
    }
  });

  ws.on('close', () => {
    console.log('❌ Клиент отключился');
  });
});

server.listen(PORT, () => {
  console.log(`🚀 Сервер запущен на порту ${PORT}`);
});
