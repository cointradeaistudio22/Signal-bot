index html
/* =========================================================
   SignalHub — complete backend
   ========================================================= */
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const pool = require('./db');
require('dotenv').config();

const app = express();
const SECRET = process.env.JWT_SECRET;
const PUBLIC_URL = process.env.PUBLIC_URL || 'http://localhost:4000';

/* ---------- Stripe (optional) ---------- */
let stripe = null;
try {
  if (process.env.STRIPE_SECRET && !process.env.STRIPE_SECRET.includes('REPLACE')) {
    stripe = require('stripe')(process.env.STRIPE_SECRET);
  }
} catch (e) { console.log('Stripe disabled:', e.message); }

app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

/* ---------- Raw body for Stripe webhook ---------- */
app.post('/api/stripe/webhook',
  express.raw({ type: 'application/json' }),
  async (req, res) => {
    if (!stripe) return res.status(400).end();
    let event;
    try {
      event = stripe.webhooks.constructEvent(
        req.body,
        req.headers['stripe-signature'],
        process.env.STRIPE_WEBHOOK_SECRET
      );
    } catch (err) {
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }
    if (event.type === 'checkout.session.completed') {
      const session = event.data.object;
      await fulfillOrder(session.metadata.order_id);
    }
    res.json({ received: true });
  }
);

/* ---------- JSON body for everything else ---------- */
app.use(express.json());

/* =========================================================
   HELPERS
   ========================================================= */
function signToken(u) { return jwt.sign({ uid: u.id, admin: u.is_admin }, SECRET, { expiresIn: '7d' }); }

function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.replace('Bearer ', '');
  try { req.user = jwt.verify(token, SECRET); next(); }
  catch { res.status(401).json({ error: 'Unauthorized' }); }
}

function adminOnly(req, res, next) {
  if (!req.user?.admin) return res.status(403).json({ error: 'Admin only' });
  next();
}

async function issueLicense(userId, botId) {
  const key = uuidv4();
  const r = await pool.query(
    `INSERT INTO licenses (user_id, bot_id, license_key, expires_at)
     VALUES ($1,$2,$3, NOW() + INTERVAL '1 year') RETURNING *`,
    [userId, botId, key]
  );
  return r.rows[0];
}

async function fulfillOrder(orderId) {
  const o = await pool.query('SELECT * FROM orders WHERE id=$1', [orderId]);
  if (!o.rows.length) return;
  const order = o.rows[0];
  if (order.status === 'paid') return;
  await pool.query('UPDATE orders SET status=$1 WHERE id=$2', ['paid', orderId]);
  await issueLicense(order.user_id, order.bot_id);
}

/* =========================================================
   AUTH
   ========================================================= */
app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Missing fields' });
  try {
    const hash = await bcrypt.hash(password, 10);
    const isAdmin = (email === process.env.ADMIN_EMAIL);
    const r = await pool.query(
      'INSERT INTO users (email,password_hash,is_admin) VALUES ($1,$2,$3) RETURNING id,email,is_admin',
      [email, hash, isAdmin]
    );
    res.json({ user: r.rows[0], token: signToken(r.rows[0]) });
  } catch { res.status(400).json({ error: 'Email exists or invalid' }); }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const r = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
  if (!r.rows.length) return res.status(401).json({ error: 'Invalid credentials' });
  const ok = await bcrypt.compare(password, r.rows[0].password_hash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
  res.json({ token: signToken(r.rows[0]), user: { id: r.rows[0].id, email: r.rows[0].email, admin: r.rows[0].is_admin } });
});

app.get('/api/me', auth, async (req, res) => {
  const r = await pool.query('SELECT id,email,is_admin FROM users WHERE id=$1', [req.user.uid]);
  res.json(r.rows[0]);
});

/* =========================================================
   BOTS
   ========================================================= */
app.get('/api/bots', async (_req, res) => {
  const r = await pool.query('SELECT * FROM bots WHERE active=true ORDER BY id');
  res.json(r.rows);
});

/* =========================================================
   PURCHASE  (Stripe if configured, else instant demo)
   ========================================================= */
app.post('/api/purchase/:botId', auth, async (req, res) => {
  const bot = await pool.query('SELECT * FROM bots WHERE id=$1 AND active=true', [req.params.botId]);
  if (!bot.rows.length) return res.status(404).json({ error: 'Bot not found' });
  const b = bot.rows[0];

  // create order
  const o = await pool.query(
    'INSERT INTO orders (user_id,bot_id,amount,status) VALUES ($1,$2,$3,$4) RETURNING *',
    [req.user.uid, b.id, b.price, 'pending']
  );
  const order = o.rows[0];

  // Stripe path
  if (stripe) {
    try {
      const session = await stripe.checkout.sessions.create({
        mode: 'payment',
        line_items: [{
          price_data: {
            currency: 'usd',
            product_data: { name: b.name },
            unit_amount: Math.round(b.price * 100)
          },
          quantity: 1
        }],
        metadata: { order_id: order.id },
        success_url: `${PUBLIC_URL}/?paid=1`,
        cancel_url: `${PUBLIC_URL}/?canceled=1`
      });
      await pool.query('UPDATE orders SET stripe_session_id=$1 WHERE id=$2', [session.id, order.id]);
      return res.json({ checkout_url: session.url });
    } catch (e) {
      return res.status(500).json({ error: 'Stripe error: ' + e.message });
    }
  }

  // DEMO path (no Stripe): mark paid instantly
  await fulfillOrder(order.id);
  const lic = await pool.query('SELECT * FROM licenses WHERE user_id=$1 AND bot_id=$2 ORDER BY id DESC LIMIT 1', [req.user.uid, b.id]);
  res.json({ demo: true, license: lic.rows[0] });
});

/* =========================================================
   LICENSE MANAGEMENT
   ========================================================= */
app.get('/api/my-licenses', auth, async (req, res) => {
  const r = await pool.query(
    `SELECT l.*, b.name AS bot_name, b.price
       FROM licenses l JOIN bots b ON b.id=l.bot_id
      WHERE l.user_id=$1 ORDER BY l.id DESC`,
    [req.user.uid]
  );
  res.json(r.rows);
});

/* ---------- MT5 heartbeat/validation ---------- */
app.post('/api/license/validate', async (req, res) => {
  const { license_key, mt5_account, broker } = req.body;
  if (!license_key) return res.json({ status: 'invalid', reason: 'no_key' });

  const r = await pool.query('SELECT * FROM licenses WHERE license_key=$1', [license_key]);
  if (!r.rows.length) return res.json({ status: 'invalid', reason: 'not_found' });

  const lic = r.rows[0];
  if (!lic.active) return res.json({ status: 'invalid', reason: 'revoked' });
  if (lic.expires_at && new Date(lic.expires_at) < new Date())
    return res.json({ status: 'expired' });

  if (!lic.mt5_account) {
    await pool.query('UPDATE licenses SET mt5_account=$1, broker=$2 WHERE id=$3',
      [String(mt5_account), broker, lic.id]);
  } else if (String(lic.mt5_account) !== String(mt5_account)) {
    return res.json({ status: 'invalid', reason: 'account_mismatch' });
  }

  res.json({ status: 'valid', bot_id: lic.bot_id, expires_at: lic.expires_at });
});

/* =========================================================
   SIGNALS
   ========================================================= */
app.get('/api/signals', async (_req, res) => {
  const r = await pool.query(
    'SELECT id,symbol,direction,entry,sl,tp,created_at FROM signals WHERE is_premium=false ORDER BY created_at DESC LIMIT 50'
  );
  res.json(r.rows);
});

app.get('/api/signals/premium', auth, async (req, res) => {
  const r = await pool.query('SELECT * FROM signals ORDER BY created_at DESC LIMIT 100');
  res.json(r.rows);
});

app.post('/api/signals', auth, adminOnly, async (req, res) => {
  const { symbol, direction, entry, sl, tp, is_premium } = req.body;
  if (!symbol || !direction) return res.status(400).json({ error: 'Missing fields' });
  const r = await pool.query(
    `INSERT INTO signals (symbol,direction,entry,sl,tp,is_premium)
     VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
    [symbol, direction.toUpperCase(), entry, sl, tp, !!is_premium]
  );
  res.json(r.rows[0]);
});

app.delete('/api/signals/:id', auth, adminOnly, async (req, res) => {
  await pool.query('DELETE FROM signals WHERE id=$1', [req.params.id]);
  res.json({ ok: true });
});

/* =========================================================
   ADMIN
   ========================================================= */
app.get('/api/admin/stats', auth, adminOnly, async (_req, res) => {
  const users = await pool.query('SELECT COUNT(*) FROM users');
  const bots  = await pool.query('SELECT COUNT(*) FROM bots');
  const orders= await pool.query("SELECT COUNT(*) FROM orders WHERE status='paid'");
  const revenue=await pool.query("SELECT COALESCE(SUM(amount),0) FROM orders WHERE status='paid'");
  const lics  = await pool.query('SELECT COUNT(*) FROM licenses');
  res.json({
    users: +users.rows[0].count,
    bots: +bots.rows[0].count,
    orders: +orders.rows[0].count,
    revenue: +revenue.rows[0].coalesce,
    licenses: +lics.rows[0].count
  });
});

app.get('/api/admin/users', auth, adminOnly, async (_req, res) => {
  const r = await pool.query('SELECT id,email,is_admin,created_at FROM users ORDER BY id DESC');
  res.json(r.rows);
});

app.get('/api/admin/licenses', auth, adminOnly, async (_req, res) => {
  const r = await pool.query(
    `SELECT l.*, u.email, b.name AS bot_name FROM licenses l
     JOIN users u ON u.id=l.user_id JOIN bots b ON b.id=l.bot_id
     ORDER BY l.id DESC`
  );
  res.json(r.rows);
});

app.post('/api/admin/licenses/:id/toggle', auth, adminOnly, async (req, res) => {
  await pool.query('UPDATE licenses SET active = NOT active WHERE id=$1', [req.params.id]);
  res.json({ ok: true });
});

app.post('/api/admin/bots', auth, adminOnly, async (req, res) => {
  const { name, description, price } = req.body;
  const r = await pool.query(
    'INSERT INTO bots (name,description,price) VALUES ($1,$2,$3) RETURNING *',
    [name, description, price || 8.90]
  );
  res.json(r.rows[0]);
});

app.post('/api/admin/bots/:id/toggle', auth, adminOnly, async (req, res) => {
  await pool.query('UPDATE bots SET active = NOT active WHERE id=$1', [req.params.id]);
  res.json({ ok: true });
});

/* =========================================================
   FALLBACK → serve index.html
   ========================================================= */
app.get('*', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

/* =========================================================
   BOOT
   ========================================================= */
(async () => {
  try {
    // ensure admin exists
    if (process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD) {
      const exists = await pool.query('SELECT 1 FROM users WHERE email=$1', [process.env.ADMIN_EMAIL]);
      if (!exists.rows.length) {
        const hash = await bcrypt.hash(process.env.ADMIN_PASSWORD, 10);
        await pool.query('INSERT INTO users (email,password_hash,is_admin) VALUES ($1,$2,TRUE)',
          [process.env.ADMIN_EMAIL, hash]);
        console.log('✔ admin created:', process.env.ADMIN_EMAIL);
      }
    }
    app.listen(process.env.PORT || 4000, () =>
      console.log('🚀 SignalHub on', PUBLIC_URL));
  } catch (e) { console.error('BOOT ERROR:', e); process.exit(1); }
})();
