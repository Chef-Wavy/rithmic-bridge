const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const rateLimit = require('express-rate-limit');
const logger = require('./lib/logger');
const RithmicPlantManager = require('./lib/plantManager');
const ProtoLoader = require('./lib/protoLoader');

const app = express();
const PORT = process.env.PORT || 3001;

// ============================================
// MIDDLEWARE
// ============================================

app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || '*',
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-User-Email']
}));

app.use(express.json());

// Rate limiting
const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 100, // 100 requests per minute
  message: { error: 'Too many requests, please try again later' }
});
app.use('/api/', limiter);

// Auth middleware
const authMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing authorization header' });
  }

  const token = authHeader.split(' ')[1];
  
  // Check if it's the bridge secret (simple auth)
  if (token === process.env.BRIDGE_SECRET) {
    req.authenticated = true;
    return next();
  }

  // Otherwise verify as JWT
  try {
    const decoded = jwt.verify(token, process.env.BRIDGE_SECRET);
    req.user = decoded;
    req.authenticated = true;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// ============================================
// GLOBALS
// ============================================

// Plant managers (one per connection type)
const plants = {
  ticker: null,
  order: null,
  history: null
};

// Active sessions
const sessions = new Map();

// Quote subscriptions
const subscriptions = new Map();

// Proto loader instance
let protoLoader = null;

// ============================================
// INITIALIZATION
// ============================================

async function initialize() {
  try {
    // Load protobuf definitions
    protoLoader = new ProtoLoader();
    await protoLoader.load();
    logger.info('Protobuf definitions loaded');

    // Initialize plant managers
    plants.ticker = new RithmicPlantManager('TICKER', protoLoader);
    plants.order = new RithmicPlantManager('ORDER', protoLoader);
    plants.history = new RithmicPlantManager('HISTORY', protoLoader);

    logger.info('Plant managers initialized');
  } catch (err) {
    logger.error('Initialization failed:', err);
  }
}

// ============================================
// API ROUTES
// ============================================

// Health check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: Date.now(),
    plants: {
      ticker: plants.ticker?.status || 'not_initialized',
      order: plants.order?.status || 'not_initialized',
      history: plants.history?.status || 'not_initialized'
    }
  });
});

// Status
app.get('/api/status', authMiddleware, (req, res) => {
  res.json({
    bridge_connected: true,
    ticker_plant: plants.ticker?.status || 'offline',
    order_plant: plants.order?.status || 'offline',
    history_plant: plants.history?.status || 'offline',
    active_sessions: sessions.size,
    active_subscriptions: subscriptions.size,
    uptime: process.uptime()
  });
});

// Heartbeat
app.get('/api/heartbeat', authMiddleware, (req, res) => {
  res.json({ success: true, timestamp: Date.now() });
});

// ============================================
// LOGIN / LOGOUT
// ============================================

app.post('/api/login', authMiddleware, async (req, res) => {
  const { username, password, system_name = 'Rithmic Test', connection_id } = req.body;
  const userEmail = req.headers['x-user-email'];

  // Only allow Test environment for safety
  if (system_name !== 'Rithmic Test' && process.env.NODE_ENV !== 'production') {
    return res.status(400).json({
      success: false,
      error: 'Only Rithmic Test environment allowed in non-production mode'
    });
  }

  const sessionId = uuidv4();

  try {
    // Use provided credentials or fall back to env vars
    const loginUser = username || process.env.RITHMIC_USER;
    const loginPass = password || process.env.RITHMIC_PASS;

    if (!loginUser || !loginPass) {
      return res.status(400).json({
        success: false,
        error: 'Credentials required'
      });
    }

    // Connect to Order plant first (primary)
    logger.info(`Attempting login for ${loginUser} to ${system_name}`);

    const loginResult = await plants.order.connect({
      username: loginUser,
      password: loginPass,
      systemName: system_name,
      sessionId
    });

    if (!loginResult.success) {
      return res.json({
        success: false,
        error: loginResult.error || 'Login failed',
        rp_code: loginResult.rpCode
      });
    }

    // Connect Ticker plant for quotes
    await plants.ticker.connect({
      username: loginUser,
      password: loginPass,
      systemName: system_name,
      sessionId
    });

    // Store session
    sessions.set(sessionId, {
      id: sessionId,
      username: loginUser,
      systemName: system_name,
      userEmail,
      connectionId: connection_id,
      accounts: loginResult.accounts || [],
      fcmId: loginResult.fcmId,
      ibId: loginResult.ibId,
      createdAt: Date.now()
    });

    // Generate session token
    const sessionToken = jwt.sign(
      { sessionId, username: loginUser },
      process.env.BRIDGE_SECRET,
      { expiresIn: '8h' }
    );

    logger.info(`Login successful for ${loginUser}, session: ${sessionId}`);

    res.json({
      success: true,
      session_token: sessionToken,
      accounts: loginResult.accounts || [],
      fcm_id: loginResult.fcmId,
      ib_id: loginResult.ibId
    });

  } catch (err) {
    logger.error('Login error:', err);
    res.status(500).json({
      success: false,
      error: err.message
    });
  }
});

app.post('/api/logout', authMiddleware, async (req, res) => {
  const { session_token } = req.body;

  try {
    if (session_token) {
      const decoded = jwt.verify(session_token, process.env.BRIDGE_SECRET);
      const session = sessions.get(decoded.sessionId);
      
      if (session) {
        // Disconnect plants
        await plants.order.disconnect(decoded.sessionId);
        await plants.ticker.disconnect(decoded.sessionId);
        sessions.delete(decoded.sessionId);
        logger.info(`Logged out session: ${decoded.sessionId}`);
      }
    }

    res.json({ success: true });
  } catch (err) {
    res.json({ success: true }); // Always return success for logout
  }
});

// ============================================
// QUOTES
// ============================================

app.post('/api/quotes/subscribe', authMiddleware, async (req, res) => {
  const { symbol, exchange = 'CME', session_token } = req.body;

  if (!symbol) {
    return res.status(400).json({ error: 'Symbol required' });
  }

  const subKey = `${exchange}:${symbol}`;

  try {
    const result = await plants.ticker.subscribe({
      symbol,
      exchange,
      type: 'QUOTE'
    });

    subscriptions.set(subKey, {
      symbol,
      exchange,
      subscribedAt: Date.now()
    });

    res.json({
      success: true,
      subscribed: true,
      symbol,
      exchange
    });
  } catch (err) {
    logger.error('Subscribe error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/quotes/unsubscribe', authMiddleware, async (req, res) => {
  const { symbol, exchange = 'CME' } = req.body;
  const subKey = `${exchange}:${symbol}`;

  try {
    await plants.ticker.unsubscribe({ symbol, exchange });
    subscriptions.delete(subKey);

    res.json({ success: true, unsubscribed: true });
  } catch (err) {
    res.json({ success: true, unsubscribed: true });
  }
});

app.get('/api/quotes/:symbol', authMiddleware, async (req, res) => {
  const { symbol } = req.params;
  const exchange = req.query.exchange || 'CME';

  try {
    const quote = await plants.ticker.getQuote(symbol, exchange);
    res.json(quote);
  } catch (err) {
    logger.error('Quote error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ============================================
// ORDERS
// ============================================

app.post('/api/orders', authMiddleware, async (req, res) => {
  const {
    order_id, symbol, exchange = 'CME', quantity, side,
    order_type = 'MARKET', price, stop_price, account_id,
    session_token, duration = 'DAY'
  } = req.body;
  const userEmail = req.headers['x-user-email'];

  // Validation
  if (!symbol || !quantity || !side || !account_id) {
    return res.status(400).json({
      error: 'Missing required fields: symbol, quantity, side, account_id'
    });
  }

  if (quantity <= 0 || quantity > 100) {
    return res.status(400).json({
      error: 'Quantity must be between 1 and 100'
    });
  }

  const orderId = order_id || uuidv4();

  try {
    const result = await plants.order.submitOrder({
      orderId,
      symbol,
      exchange,
      quantity,
      isBuy: side.toUpperCase() === 'BUY',
      orderType: order_type.toUpperCase(),
      price,
      stopPrice: stop_price,
      accountId: account_id,
      duration
    });

    logger.info(`Order submitted: ${orderId} ${side} ${quantity} ${symbol}`);

    res.json({
      success: result.success,
      order_id: orderId,
      rithmic_order_id: result.rithmicOrderId,
      symbol,
      side: side.toUpperCase(),
      quantity,
      order_type: order_type.toUpperCase(),
      status: result.status || 'PENDING',
      fill_price: result.fillPrice,
      fill_qty: result.fillQty,
      error: result.error,
      timestamp: Date.now()
    });

  } catch (err) {
    logger.error('Order error:', err);
    res.status(500).json({
      success: false,
      error: err.message
    });
  }
});

app.post('/api/orders/bracket', authMiddleware, async (req, res) => {
  const {
    bracket_id, symbol, exchange = 'CME', quantity, side,
    entry_type = 'MARKET', entry_price, take_profit_price,
    stop_loss_price, account_id, session_token
  } = req.body;

  if (!symbol || !quantity || !side || !take_profit_price || !stop_loss_price) {
    return res.status(400).json({
      error: 'Missing required bracket fields'
    });
  }

  const bracketId = bracket_id || uuidv4();})
