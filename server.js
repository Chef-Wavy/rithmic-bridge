/**
 * RITHMIC BRIDGE SERVER - SINGLE FILE VERSION (MULTI-USER)
 * 
 * Deploy to Railway, Render, or any Node.js host.
 * 
 * Environment Variables:
 * - BRIDGE_SECRET: Shared secret for auth with Base44
 * - PORT: Server port (default 3001)
 * 
 * Usage:
 * 1. Create new GitHub repo
 * 2. Create package.json with: {"scripts":{"start":"node server.js"},"dependencies":{"express":"^4.18.2","cors":"^2.8.5","jsonwebtoken":"^9.0.2","uuid":"^9.0.0","express-rate-limit":"^7.1.5","ws":"^8.14.2"}}
 * 3. Create server.js with this file's contents
 * 4. Push to GitHub, deploy on Railway
 * 5. Set BRIDGE_SECRET environment variable
 */

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const rateLimit = require('express-rate-limit');
const http = require('http');
const WebSocket = require('ws');

const app = express();
const PORT = process.env.PORT || 3001;
const BRIDGE_SECRET = process.env.BRIDGE_SECRET || 'change-me-in-production';

// ============================================
// MIDDLEWARE
// ============================================

app.use(cors({ origin: '*', methods: ['GET', 'POST', 'OPTIONS'], allowedHeaders: ['Content-Type', 'Authorization', 'X-User-Email', 'X-User-Id'] }));
app.use(express.json());

const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  keyGenerator: (req) => req.headers['x-user-id'] || req.ip,
  message: { error: 'Too many requests' }
});
app.use('/api/', limiter);

const authMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing authorization' });
  }
  const token = authHeader.split(' ')[1];
  if (token === BRIDGE_SECRET) {
    req.authenticated = true;
    return next();
  }
  try {
    req.user = jwt.verify(token, BRIDGE_SECRET);
    req.authenticated = true;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// ============================================
// USER SESSION STORAGE
// ============================================

const userSessions = new Map();
const SESSION_TIMEOUT = 8 * 60 * 60 * 1000;

// Cleanup inactive sessions
setInterval(() => {
  const now = Date.now();
  for (const [userId, session] of userSessions.entries()) {
    if (now - session.lastActivity > SESSION_TIMEOUT) {
      console.log(`Cleaning up session: ${userId}`);
      userSessions.delete(userId);
    }
  }
}, 30 * 60 * 1000);

function getSession(userId) {
  const session = userSessions.get(userId);
  if (session) session.lastActivity = Date.now();
  return session;
}

// ============================================
// MOCK PRICE DATA (Replace with real Rithmic connection)
// ============================================

const basePrices = {
  'ES': 5025.00, 'NQ': 17750.00, 'YM': 38500.00, 'RTY': 2050.00,
  'CL': 78.50, 'NG': 2.85, 'GC': 1985.00, 'SI': 23.50,
  'ZB': 118.50, 'ZN': 110.25, '6E': 1.0850, '6J': 0.0067,
};

function getMockPrice(symbol) {
  const base = basePrices[symbol.toUpperCase()] || 1000;
  return base + (Math.random() - 0.5) * (base * 0.002);
}

function getMockQuote(symbol, exchange = 'CME') {
  const price = getMockPrice(symbol);
  return {
    symbol: symbol.toUpperCase(),
    exchange,
    bid: price - 0.25,
    bid_size: Math.floor(Math.random() * 100) + 10,
    ask: price + 0.25,
    ask_size: Math.floor(Math.random() * 100) + 10,
    last: price,
    last_size: Math.floor(Math.random() * 20) + 1,
    volume: Math.floor(Math.random() * 500000) + 100000,
    change: (Math.random() - 0.5) * 20,
    high: price + Math.random() * 10,
    low: price - Math.random() * 10,
    timestamp: Date.now(),
    mock: true
  };
}

// ============================================
// API ROUTES
// ============================================

// Health check (no auth)
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', mode: 'multi-user-mock', timestamp: Date.now(), active_sessions: userSessions.size });
});

// Status
app.get('/api/status', authMiddleware, (req, res) => {
  const userId = req.headers['x-user-id'];
  const session = userId ? getSession(userId) : null;
  res.json({
    bridge_connected: true,
    mode: 'multi-user-mock',
    user_connected: !!session,
    ticker_plant: session ? 'mock' : 'not_connected',
    order_plant: session ? 'mock' : 'not_connected',
    active_sessions: userSessions.size,
    uptime: process.uptime()
  });
});

// Heartbeat
app.get('/api/heartbeat', authMiddleware, (req, res) => {
  res.json({ success: true, timestamp: Date.now() });
});

// Login
app.post('/api/login', authMiddleware, async (req, res) => {
  const { username, password, system_name = 'Rithmic Test' } = req.body;
  const userId = req.headers['x-user-id'];
  const userEmail = req.headers['x-user-email'];

  if (!userId) return res.status(400).json({ error: 'X-User-Id header required' });
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

  console.log(`Login: ${userId} (${username}) to ${system_name}`);

  // Create session token
  const sessionToken = jwt.sign({ userId, username }, BRIDGE_SECRET, { expiresIn: '8h' });

  // Mock accounts (in real version, these come from Rithmic)
  const accounts = [
    { account_id: 'SIM001', account_name: 'Demo Account 1', fcm_id: 'FCM1', ib_id: 'IB1' },
    { account_id: 'SIM002', account_name: 'Demo Account 2', fcm_id: 'FCM1', ib_id: 'IB1' },
  ];

  // Store session
  userSessions.set(userId, {
    username,
    userEmail,
    systemName: system_name,
    accounts,
    sessionToken,
    subscriptions: new Set(),
    orders: [],
    positions: [],
    createdAt: Date.now(),
    lastActivity: Date.now()
  });

  res.json({
    success: true,
    session_token: sessionToken,
    accounts,
    fcm_id: 'FCM1',
    ib_id: 'IB1',
    message: `Connected to ${system_name} (mock mode)`
  });
});

// Logout
app.post('/api/logout', authMiddleware, (req, res) => {
  const userId = req.headers['x-user-id'];
  if (userId) {
    userSessions.delete(userId);
    console.log(`Logout: ${userId}`);
  }
  res.json({ success: true });
});

// Subscribe to quotes
app.post('/api/quotes/subscribe', authMiddleware, (req, res) => {
  const { symbol, exchange = 'CME' } = req.body;
  const userId = req.headers['x-user-id'];
  const session = getSession(userId);

  if (!session) return res.status(401).json({ error: 'No active session' });
  if (!symbol) return res.status(400).json({ error: 'Symbol required' });

  session.subscriptions.add(`${exchange}:${symbol.toUpperCase()}`);
  res.json({ success: true, subscribed: true, symbol: symbol.toUpperCase(), exchange });
});

// Unsubscribe
app.post('/api/quotes/unsubscribe', authMiddleware, (req, res) => {
  const { symbol, exchange = 'CME' } = req.body;
  const userId = req.headers['x-user-id'];
  const session = getSession(userId);

  if (session) session.subscriptions.delete(`${exchange}:${symbol.toUpperCase()}`);
  res.json({ success: true, unsubscribed: true });
});

// Get quote
app.get('/api/quotes/:symbol', authMiddleware, (req, res) => {
  const { symbol } = req.params;
  const exchange = req.query.exchange || 'CME';
  res.json(getMockQuote(symbol, exchange));
});

// Submit order
app.post('/api/orders', authMiddleware, (req, res) => {
  const { symbol, exchange = 'CME', quantity, side, order_type = 'MARKET', price, account_id } = req.body;
  const userId = req.headers['x-user-id'];
  const session = getSession(userId);

  if (!session) return res.status(401).json({ error: 'No active session' });
  if (!symbol || !quantity || !side || !account_id) {
    return res.status(400).json({ error: 'Missing: symbol, quantity, side, account_id' });
  }

  const orderId = uuidv4();
  const fillPrice = getMockPrice(symbol);

  const order = {
    order_id: orderId,
    symbol: symbol.toUpperCase(),
    exchange,
    side: side.toUpperCase(),
    quantity,
    order_type: order_type.toUpperCase(),
    price: price || fillPrice,
    fill_price: fillPrice,
    fill_qty: quantity,
    status: 'FILLED',
    account_id,
    timestamp: Date.now()
  };

  session.orders.push(order);

  // Update position
  const posIdx = session.positions.findIndex(p => p.symbol === symbol.toUpperCase());
  const qtyChange = side.toUpperCase() === 'BUY' ? quantity : -quantity;
  
  if (posIdx >= 0) {
    session.positions[posIdx].net_qty += qtyChange;
    if (session.positions[posIdx].net_qty === 0) {
      session.positions.splice(posIdx, 1);
    }
  } else if (qtyChange !== 0) {
    session.positions.push({
      symbol: symbol.toUpperCase(),
      exchange,
      account_id,
      net_qty: qtyChange,
      avg_price: fillPrice,
      open_pnl: 0
    });
  }

  console.log(`Order: ${userId} ${side} ${quantity} ${symbol} @ ${fillPrice.toFixed(2)}`);

  res.json({
    success: true,
    ...order,
    rithmic_order_id: 'MOCK_' + orderId.slice(0, 8),
    mock: true
  });
});

// Cancel order
app.post('/api/orders/:orderId/cancel', authMiddleware, (req, res) => {
  const { orderId } = req.params;
  res.json({ success: true, order_id: orderId, status: 'CANCELLED', timestamp: Date.now() });
});

// Get orders
app.get('/api/orders', authMiddleware, (req, res) => {
  const userId = req.headers['x-user-id'];
  const session = getSession(userId);
  if (!session) return res.status(401).json({ error: 'No active session' });
  res.json({ orders: session.orders.slice(-50) });
});

// Get positions
app.get('/api/positions', authMiddleware, (req, res) => {
  const userId = req.headers['x-user-id'];
  const session = getSession(userId);
  if (!session) return res.status(401).json({ error: 'No active session' });
  res.json({ positions: session.positions });
});

// Get accounts
app.get('/api/accounts', authMiddleware, (req, res) => {
  const userId = req.headers['x-user-id'];
  const session = getSession(userId);
  if (!session) return res.status(401).json({ error: 'No active session' });
  res.json({ accounts: session.accounts });
});

// Bracket order
app.post('/api/orders/bracket', authMiddleware, (req, res) => {
  const { symbol, quantity, side, take_profit_price, stop_loss_price, account_id } = req.body;
  const userId = req.headers['x-user-id'];
  const session = getSession(userId);

  if (!session) return res.status(401).json({ error: 'No active session' });

  const bracketId = uuidv4();
  const entryPrice = getMockPrice(symbol);

  res.json({
    success: true,
    bracket_id: bracketId,
    entry_order: { order_id: 'E_' + bracketId.slice(0, 8), status: 'FILLED', fill_price: entryPrice },
    take_profit_order: { order_id: 'TP_' + bracketId.slice(0, 8), status: 'WORKING', price: take_profit_price },
    stop_loss_order: { order_id: 'SL_' + bracketId.slice(0, 8), status: 'WORKING', price: stop_loss_price },
    mock: true
  });
});

// ============================================
// WEBSOCKET
// ============================================

const server = http.createServer(app);
const wss = new WebSocket.Server({ server, path: '/ws' });

wss.on('connection', (ws) => {
  console.log('WebSocket connected');
  ws.isAlive = true;
  ws.userId = null;
  ws.subscriptions = new Set();

  ws.on('pong', () => { ws.isAlive = true; });

  ws.on('message', (data) => {
    try {
      const msg = JSON.parse(data);
      switch (msg.type) {
        case 'auth':
          if (msg.token === BRIDGE_SECRET || (msg.user_id && getSession(msg.user_id))) {
            ws.userId = msg.user_id;
            ws.send(JSON.stringify({ type: 'authenticated', user_id: ws.userId }));
          }
          break;
        case 'subscribe':
          ws.subscriptions.add(`${msg.exchange || 'CME'}:${msg.symbol}`);
          ws.send(JSON.stringify({ type: 'subscribed', symbol: msg.symbol }));
          break;
        case 'unsubscribe':
          ws.subscriptions.delete(`${msg.exchange || 'CME'}:${msg.symbol}`);
          break;
        case 'ping':
          ws.send(JSON.stringify({ type: 'pong', timestamp: Date.now() }));
          break;
      }
    } catch (e) { console.error('WS error:', e); }
  });

  ws.on('close', () => console.log('WebSocket disconnected'));
});

// Heartbeat
setInterval(() => {
  wss.clients.forEach((ws) => {
    if (!ws.isAlive) return ws.terminate();
    ws.isAlive = false;
    ws.ping();
  });
}, 30000);

// Stream mock quotes to subscribers
setInterval(() => {
  wss.clients.forEach((ws) => {
    if (ws.readyState !== WebSocket.OPEN) return;
    ws.subscriptions.forEach((key) => {
      const [exchange, symbol] = key.split(':');
      ws.send(JSON.stringify({ type: 'quote', ...getMockQuote(symbol, exchange) }));
    });
  });
}, 1000);

// ============================================
// START
// ============================================

server.listen(PORT, () => {
  console.log(`Rithmic Bridge (Multi-User Mock) running on port ${PORT}`);
  console.log(`Secret configured: ${BRIDGE_SECRET !== 'change-me-in-production' ? 'Yes' : 'NO - SET BRIDGE_SECRET!'}`);
});