import express from 'express';
import pg from 'pg';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import Razorpay from 'razorpay';
import { z } from 'zod';
import { OAuth2Client } from 'google-auth-library';

const { DATABASE_URL, GOOGLE_CLIENT_ID, RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET,
  RAZORPAY_WEBHOOK_SECRET, SESSION_SECRET, ADMIN_EMAIL } = process.env;
const db = new pg.Pool({ connectionString: DATABASE_URL });
const google = new OAuth2Client(GOOGLE_CLIENT_ID);
const rzp = new Razorpay({ key_id: RAZORPAY_KEY_ID, key_secret: RAZORPAY_KEY_SECRET });
const app = express();
app.use(helmet());

// ---------- helpers ----------
const wrap = fn => (req, res, next) => fn(req, res, next).catch(e => {
  console.error(e); res.status(e.status || 500).json({ error: e.status ? e.message : 'Server error' });
});
const fail = (status, message) => Object.assign(new Error(message), { status });
const audit = (c, actor, action, entity, id, meta = {}) =>
  c.query('INSERT INTO audit_logs(actor_id,action,entity,entity_id,meta) VALUES($1,$2,$3,$4,$5)',
    [actor, action, entity, id, meta]);
const tx = async fn => {
  const c = await db.connect();
  try { await c.query('BEGIN'); const r = await fn(c); await c.query('COMMIT'); return r; }
  catch (e) { await c.query('ROLLBACK'); throw e; } finally { c.release(); }
};

// Role is always re-read from DB, never trusted from the token.
const auth = wrap(async (req, _res, next) => {
  const t = (req.headers.authorization || '').replace('Bearer ', '');
  let p; try { p = jwt.verify(t, SESSION_SECRET); } catch { throw fail(401, 'Not signed in'); }
  const { rows } = await db.query('SELECT * FROM users WHERE id=$1', [p.sub]);
  if (!rows[0] || rows[0].status !== 'active') throw fail(403, 'Account unavailable');
  req.user = rows[0]; next();
});
const requireRole = (...roles) => (req, _res, next) =>
  roles.includes(req.user.role) ? next()
    : next(fail(403, 'You need Creator Access to create tournaments.'));
const limiter = (max) => rateLimit({ windowMs: 15 * 60 * 1000, max });

// ---------- webhook (raw body, registered BEFORE express.json) ----------
async function markPaid(c, orderId, paymentId) {
  const { rows } = await c.query(
    `UPDATE payments SET status='paid', razorpay_payment_id=$2, paid_at=now()
     WHERE razorpay_order_id=$1 AND status<>'paid' RETURNING *`, [orderId, paymentId]);
  const p = rows[0]; if (!p) return; // already processed: idempotent
  if (p.kind === 'entry') {
    await c.query(`UPDATE tournament_registrations SET status='confirmed' WHERE id=$1`, [p.registration_id]);
    await c.query(`INSERT INTO notifications(user_id,title) VALUES($1,'Payment successful')`, [p.user_id]);
  } else {
    await c.query(`UPDATE tournaments SET creator_fee_paid=true WHERE id=$1`, [p.tournament_id]);
  }
  await audit(c, p.user_id, 'payment.paid', 'payment', p.id);
}
app.post('/webhooks/razorpay', express.raw({ type: 'application/json' }), wrap(async (req, res) => {
  const sig = req.headers['x-razorpay-signature'] || '';
  const exp = crypto.createHmac('sha256', RAZORPAY_WEBHOOK_SECRET).update(req.body).digest('hex');
  if (sig.length !== exp.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(exp)))
    throw fail(400, 'Bad signature');
  const ev = JSON.parse(req.body);
  if (ev.event === 'payment.captured') {
    const pay = ev.payload.payment.entity;
    await tx(c => markPaid(c, pay.order_id, pay.id));
  }
  res.json({ ok: true });
}));

app.use(express.json({ limit: '100kb' }));

// ---------- auth ----------
app.post('/auth/google', limiter(30), wrap(async (req, res) => {
  const { idToken } = z.object({ idToken: z.string() }).parse(req.body);
  const ticket = await google.verifyIdToken({ idToken, audience: GOOGLE_CLIENT_ID });
  const g = ticket.getPayload();
  const user = await tx(async c => {
    let { rows } = await c.query('SELECT * FROM users WHERE google_sub=$1', [g.sub]);
    if (!rows[0]) {
      // First-admin bootstrap: only the ADMIN_EMAIL (server env) while no admin exists.
      const { rows: a } = await c.query(`SELECT 1 FROM users WHERE role='admin' LIMIT 1`);
      const role = !a[0] && g.email_verified && g.email === ADMIN_EMAIL ? 'admin' : 'player';
      ({ rows } = await c.query(
        `INSERT INTO users(google_sub,email,name,photo_url,role) VALUES($1,$2,$3,$4,$5) RETURNING *`,
        [g.sub, g.email, g.name, g.picture, role]));
      await audit(c, rows[0].id, 'user.created', 'user', rows[0].id, { role });
    }
    return rows[0];
  });
  if (user.status !== 'active') throw fail(403, 'Account suspended');
  const token = jwt.sign({ sub: user.id }, SESSION_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user.id, name: user.name, email: user.email, photo: user.photo_url, role: user.role } });
}));

// ---------- creator access codes ----------
app.post('/admin/codes', auth, requireRole('admin'), wrap(async (req, res) => {
  const b = z.object({ maxUses: z.number().int().min(1).default(1), expiresAt: z.string().datetime().optional() }).parse(req.body);
  const code = crypto.randomBytes(6).toString('hex').toUpperCase(); // shown ONCE
  const hash = await bcrypt.hash(code, 10);
  const { rows } = await db.query(
    'INSERT INTO creator_access_codes(code_hash,created_by,max_uses,expires_at) VALUES($1,$2,$3,$4) RETURNING code_id',
    [hash, req.user.id, b.maxUses, b.expiresAt || null]);
  await audit(db, req.user.id, 'code.created', 'code', rows[0].code_id);
  res.json({ codeId: rows[0].code_id, code });
}));
app.post('/admin/codes/:id/disable', auth, requireRole('admin'), wrap(async (req, res) => {
  await db.query(`UPDATE creator_access_codes SET status='disabled' WHERE code_id=$1`, [req.params.id]);
  await audit(db, req.user.id, 'code.disabled', 'code', req.params.id);
  res.json({ ok: true });
}));
app.post('/creator/redeem', auth, limiter(10), wrap(async (req, res) => {
  const { code } = z.object({ code: z.string().min(4).max(64) }).parse(req.body);
  const { rows } = await db.query(
    `SELECT * FROM creator_access_codes WHERE status='active' AND used_count<max_uses
     AND (expires_at IS NULL OR expires_at>now())`);
  let match = null;
  for (const r of rows) if (await bcrypt.compare(code.trim().toUpperCase(), r.code_hash)) { match = r; break; }
  if (!match) throw fail(400, 'Invalid or expired code');
  await tx(async c => {
    // Atomic increment: concurrent redemptions cannot exceed max_uses.
    const u = await c.query(
      `UPDATE creator_access_codes SET used_count=used_count+1
       WHERE code_id=$1 AND status='active' AND used_count<max_uses AND (expires_at IS NULL OR expires_at>now())`,
      [match.code_id]);
    if (!u.rowCount) throw fail(400, 'Invalid or expired code');
    await c.query(
      `UPDATE users SET role='creator', creator_granted_at=now(), creator_granted_via=$2
       WHERE id=$1 AND role='player'`, [req.user.id, match.code_id]);
    await audit(c, req.user.id, 'creator.granted', 'code', match.code_id);
  });
  res.json({ role: req.user.role === 'admin' ? 'admin' : 'creator' });
}));

// ---------- tournaments ----------
app.get('/tournaments', wrap(async (_req, res) => {
  const { rows } = await db.query(
    `SELECT t.id,t.name,t.mode,t.starts_at,t.reg_end,t.min_players,t.max_players,t.entry_fee_paise,
            t.prize_pool,t.status,t.banner_url,t.published_at,
            (SELECT count(*) FROM tournament_registrations r WHERE r.tournament_id=t.id
              AND r.status IN ('payment_pending','confirmed'))::int AS registered
     FROM tournaments t WHERE t.status NOT IN ('draft','cancelled')
     ORDER BY t.published_at DESC, t.starts_at ASC LIMIT 100`);
  res.json(rows);
}));
const tSchema = z.object({
  name: z.string().min(3).max(80), description: z.string().max(2000).optional(),
  mode: z.enum(['BR', 'CS']), startsAt: z.string().datetime(),
  regStart: z.string().datetime(), regEnd: z.string().datetime(),
  minPlayers: z.number().int().min(1), maxPlayers: z.number().int().min(1).max(1000),
  entryFeePaise: z.number().int().min(0), prizePool: z.string().max(200).optional(),
  rules: z.string().max(5000).optional(), bannerUrl: z.string().url().optional(),
});
app.post('/tournaments', auth, requireRole('creator', 'admin'), wrap(async (req, res) => {
  const b = tSchema.parse(req.body);
  const { rows } = await db.query(
    `INSERT INTO tournaments(owner_id,name,description,mode,starts_at,reg_start,reg_end,min_players,
     max_players,entry_fee_paise,prize_pool,rules,banner_url) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
     RETURNING id`,
    [req.user.id, b.name, b.description, b.mode, b.startsAt, b.regStart, b.regEnd, b.minPlayers,
     b.maxPlayers, b.entryFeePaise, b.prizePool, b.rules, b.bannerUrl]);
  await audit(db, req.user.id, 'tournament.created', 'tournament', rows[0].id);
  res.json({ id: rows[0].id });
}));
async function ownedTournament(req) {
  const { rows } = await db.query('SELECT * FROM tournaments WHERE id=$1', [req.params.id]);
  const t = rows[0];
  if (!t) throw fail(404, 'Not found');
  if (req.user.role !== 'admin' && t.owner_id !== req.user.id) throw fail(403, 'Not your tournament');
  return t;
}
// Creator fee: amount comes from DB settings; admin is exempt via role.
app.post('/tournaments/:id/creator-fee', auth, requireRole('creator'), wrap(async (req, res) => {
  const t = await ownedTournament(req);
  if (t.creator_fee_paid) throw fail(409, 'Already paid');
  const { rows } = await db.query(`SELECT value FROM platform_settings WHERE key='creator_fee_paise'`);
  const amount = parseInt(rows[0].value, 10);
  const order = await rzp.orders.create({ amount, currency: 'INR', receipt: `cf_${t.id.slice(0, 30)}` });
  await db.query(`INSERT INTO payments(kind,user_id,tournament_id,amount_paise,razorpay_order_id)
    VALUES('creator_fee',$1,$2,$3,$4)`, [req.user.id, t.id, amount, order.id]);
  res.json({ orderId: order.id, amount, keyId: RAZORPAY_KEY_ID });
}));
app.post('/tournaments/:id/publish', auth, requireRole('creator', 'admin'), wrap(async (req, res) => {
  const t = await ownedTournament(req);
  if (t.status !== 'draft') throw fail(409, 'Already published');
  if (req.user.role !== 'admin' && !t.creator_fee_paid) throw fail(402, 'Creator fee unpaid');
  await tx(async c => {
    await c.query(`UPDATE tournaments SET status='registration_open', published_at=now() WHERE id=$1`, [t.id]);
    await c.query(`INSERT INTO notifications(user_id,title,body)
      SELECT id,'New tournament announced',$1 FROM users WHERE status='active'`, [t.name]);
    await audit(c, req.user.id, 'tournament.published', 'tournament', t.id);
  });
  res.json({ ok: true });
}));

// ---------- join ----------
app.post('/tournaments/:id/join', auth, limiter(60), wrap(async (req, res) => {
  const b = z.object({ ffUid: z.string().regex(/^\d{6,15}$/), nickname: z.string().min(2).max(30),
    region: z.string().max(20).optional() }).parse(req.body);
  const out = await tx(async c => {
    const { rows } = await c.query('SELECT * FROM tournaments WHERE id=$1 FOR UPDATE', [req.params.id]);
    const t = rows[0];
    if (!t) throw fail(404, 'Not found');
    const now = new Date();
    if (t.status !== 'registration_open' || now < t.reg_start || now > t.reg_end) throw fail(409, 'Registration closed');
    const { rows: [{ n }] } = await c.query(
      `SELECT count(*)::int n FROM tournament_registrations WHERE tournament_id=$1 AND status IN ('payment_pending','confirmed')`, [t.id]);
    if (n >= t.max_players) throw fail(409, 'Tournament full');
    const paid = t.entry_fee_paise > 0;
    let reg;
    try {
      ({ rows: [reg] } = await c.query(
        `INSERT INTO tournament_registrations(tournament_id,user_id,ff_uid,ff_nickname,status)
         VALUES($1,$2,$3,$4,$5) RETURNING id`,
        [t.id, req.user.id, b.ffUid, b.nickname, paid ? 'payment_pending' : 'confirmed']));
    } catch (e) { if (e.code === '23505') throw fail(409, 'Already registered (or this UID is taken)'); throw e; }
    await c.query(`INSERT INTO free_fire_profiles(user_id,uid,nickname,region) VALUES($1,$2,$3,$4)
      ON CONFLICT (user_id) DO UPDATE SET uid=$2,nickname=$3,region=$4,updated_at=now()`,
      [req.user.id, b.ffUid, b.nickname, b.region]);
    let order = null;
    if (paid) { // price read from DB, never from the client
      order = await rzp.orders.create({ amount: t.entry_fee_paise, currency: 'INR', receipt: `reg_${reg.id.slice(0, 30)}` });
      await c.query(`INSERT INTO payments(kind,user_id,tournament_id,registration_id,amount_paise,razorpay_order_id)
        VALUES('entry',$1,$2,$3,$4,$5)`, [req.user.id, t.id, reg.id, t.entry_fee_paise, order.id]);
    }
    await audit(c, req.user.id, 'registration.created', 'registration', reg.id);
    return { registrationId: reg.id, order: order && { orderId: order.id, amount: t.entry_fee_paise, keyId: RAZORPAY_KEY_ID } };
  });
  res.json(out);
}));

// Client reports success -> we verify the signature ourselves.
app.post('/payments/verify', auth, wrap(async (req, res) => {
  const b = z.object({ orderId: z.string(), paymentId: z.string(), signature: z.string() }).parse(req.body);
  const exp = crypto.createHmac('sha256', RAZORPAY_KEY_SECRET).update(`${b.orderId}|${b.paymentId}`).digest('hex');
  if (b.signature.length !== exp.length || !crypto.timingSafeEqual(Buffer.from(b.signature), Buffer.from(exp)))
    throw fail(400, 'Payment verification failed');
  const { rows } = await db.query('SELECT user_id FROM payments WHERE razorpay_order_id=$1', [b.orderId]);
  if (!rows[0] || rows[0].user_id !== req.user.id) throw fail(403, 'Not your payment');
  await tx(c => markPaid(c, b.orderId, b.paymentId));
  res.json({ ok: true });
}));

// ---------- manual Free Fire ID verification ----------
app.patch('/registrations/:id/verification', auth, requireRole('creator', 'admin'), wrap(async (req, res) => {
  const { status } = z.object({ status: z.enum(['verified', 'rejected']) }).parse(req.body);
  const { rows } = await db.query(
    `SELECT r.*, t.owner_id FROM tournament_registrations r JOIN tournaments t ON t.id=r.tournament_id WHERE r.id=$1`, [req.params.id]);
  const r = rows[0];
  if (!r) throw fail(404, 'Not found');
  if (req.user.role !== 'admin' && r.owner_id !== req.user.id) throw fail(403, 'Not your tournament');
  await tx(async c => {
    await c.query('UPDATE tournament_registrations SET verification_status=$2 WHERE id=$1', [r.id, status]);
    await c.query(`INSERT INTO notifications(user_id,title) VALUES($1,$2)`, [r.user_id, `Free Fire ID ${status}`]);
    await audit(c, req.user.id, `ffid.${status}`, 'registration', r.id);
  });
  res.json({ ok: true });
}));

app.listen(process.env.PORT || 3000, () => console.log('API up'));
