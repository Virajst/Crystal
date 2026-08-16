const crypto = require('crypto');
const argon2 = require('argon2');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');
const { verifySync } = require('otplib');

const User = mongoose.models.User || mongoose.model('User', new mongoose.Schema({
  email: { type: String, lowercase: true, trim: true, index: true },
  name: { type: String, trim: true },
  passwordHash: String,
  providers: [{ name: String, id: String }],
  avatarUrl: String,
  emailVerified: { type: Boolean, default: false },
  emailVerification: { tokenHash: String, expiresAt: Date },
  passwordReset: { tokenHash: String, expiresAt: Date },
  mfa: { enabled: { type: Boolean, default: false }, secret: String, backupCodes: [String] }
}, { timestamps: true, collection: 'users' }));

const AuditLog = mongoose.models.AuditLog || mongoose.model('AuditLog', new mongoose.Schema({
  event: String, userId: String, email: String, ip: String, userAgent: String, meta: mongoose.Schema.Types.Mixed
}, { timestamps: true, collection: 'audit_logs' }));

const hashToken = value => crypto.createHash('sha256').update(value).digest('hex');
const token = () => crypto.randomBytes(32).toString('base64url');
const backupCode = () => crypto.randomBytes(8).toString('hex').toUpperCase();

function encryptionKey() {
  const raw = Buffer.from(process.env.TOTP_ENCRYPTION_KEY || '', 'base64');
  if (raw.length !== 32) throw new Error('TOTP_ENCRYPTION_KEY must be a base64-encoded 32-byte key');
  return raw;
}
function decrypt(value) {
  const [ivB64, tagB64, dataB64] = value.split('.');
  const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey(), Buffer.from(ivB64, 'base64'));
  decipher.setAuthTag(Buffer.from(tagB64, 'base64'));
  return Buffer.concat([decipher.update(Buffer.from(dataB64, 'base64')), decipher.final()]).toString('utf8');
}
function encrypt(value) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey(), iv);
  const data = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
  return [iv, cipher.getAuthTag(), data].map(x => x.toString('base64')).join('.');
}

async function audit(req, event, user, meta = {}) {
  try { await AuditLog.create({ event, userId: user?.id, email: user?.email, ip: req.ip, userAgent: req.get('user-agent'), meta }); } catch (e) { console.error('audit log failed', e.message); }
}

function mailer() {
  if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
    return nodemailer.createTransport({ host: process.env.SMTP_HOST, port: Number(process.env.SMTP_PORT || 587), secure: process.env.SMTP_SECURE === 'true', auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } });
  }
  return null;
}
async function sendMail(to, subject, text) {
  const from = process.env.MAIL_FROM || 'CRYSTAL <no-reply@example.com>';
  const transport = mailer();
  if (!transport) { console.log(`[CRYSTAL DEV EMAIL] To: ${to}\nSubject: ${subject}\n\n${text}`); return; }
  await transport.sendMail({ from, to, subject, text });
}

function rotateSession(req, user, cb) {
  req.session.regenerate(err => {
    if (err) return cb(err);
    req.login(user, cb);
  });
}

module.exports = function installSecurity(app) {
  app.get('/api/csrf', (req, res) => {
    if (!req.session.csrfToken) req.session.csrfToken = token();
    res.json({ token: req.session.csrfToken });
  });

  app.use((req, res, next) => {
    if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) return next();
    const protectedPath = req.path.startsWith('/auth/') || req.path.startsWith('/api/');
    if (!protectedPath) return next();
    const expected = req.session.csrfToken;
    const supplied = req.get('x-csrf-token');
    if (!expected || !supplied || !crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(supplied))) {
      audit(req, 'csrf_failure', req.user).catch(() => {});
      return res.status(403).json({ error: 'Invalid security token' });
    }
    next();
  });

  app.post('/auth/register', async (req, res) => {
    try {
      const email = String(req.body.email || '').toLowerCase().trim();
      const password = String(req.body.password || '');
      const name = String(req.body.name || '').trim();
      if (!email || password.length < 12 || password.length > 128) return res.status(400).json({ error: 'Use a valid email and a password between 12 and 128 characters' });
      const exists = await User.exists({ email });
      if (exists) return res.status(400).json({ error: 'Unable to create account with those details' });
      const raw = token();
      const user = await User.create({ email, name: name || email, passwordHash: await argon2.hash(password, { type: argon2.argon2id }), emailVerified: false, emailVerification: { tokenHash: hashToken(raw), expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000) } });
      const url = `${process.env.APP_URL || 'http://localhost:3000'}/verify-email?token=${encodeURIComponent(raw)}`;
      await sendMail(email, 'Verify your CRYSTAL email', `Verify your CRYSTAL account: ${url}\n\nThis link expires in 24 hours.`);
      await audit(req, 'registration', user);
      res.status(201).json({ ok: true, verificationRequired: true });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Registration failed' }); }
  });

  app.get('/auth/verify-email', async (req, res) => {
    try {
      const raw = String(req.query.token || '');
      const user = await User.findOne({ 'emailVerification.tokenHash': hashToken(raw), 'emailVerification.expiresAt': { $gt: new Date() } });
      if (!user) return res.status(400).json({ error: 'Verification link is invalid or expired' });
      user.emailVerified = true; user.emailVerification = undefined; await user.save();
      await audit(req, 'email_verified', user);
      res.redirect('/?verified=1');
    } catch { res.status(400).json({ error: 'Verification failed' }); }
  });

  app.post('/auth/resend-verification', async (req, res) => {
    const email = String(req.body.email || '').toLowerCase().trim();
    const user = await User.findOne({ email });
    if (user && !user.emailVerified) {
      const raw = token(); user.emailVerification = { tokenHash: hashToken(raw), expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000) }; await user.save();
      const url = `${process.env.APP_URL || 'http://localhost:3000'}/verify-email?token=${encodeURIComponent(raw)}`;
      await sendMail(email, 'Verify your CRYSTAL email', `Verify your CRYSTAL account: ${url}`);
    }
    res.json({ ok: true, message: 'If an account requires verification, an email has been sent.' });
  });

  app.post('/auth/login', async (req, res) => {
    try {
      const email = String(req.body.email || '').toLowerCase().trim();
      const password = String(req.body.password || '');
      const user = await User.findOne({ email });
      const valid = !!user?.passwordHash && await argon2.verify(user.passwordHash, password).catch(() => false);
      if (!valid) { await audit(req, 'login_failure', user, { reason: 'invalid_credentials' }); return res.status(401).json({ error: 'Invalid email or password' }); }
      if (!user.emailVerified) return res.status(403).json({ error: 'Please verify your email before signing in' });
      rotateSession(req, user, async err => {
        if (err) return res.status(500).json({ error: 'Login failed' });
        if (!req.session.csrfToken) req.session.csrfToken = token();
        if (user.mfa?.enabled) req.session.mfaPending = true;
        await audit(req, 'login_success', user);
        res.json({ ok: true, mfaRequired: !!user.mfa?.enabled });
      });
    } catch { res.status(500).json({ error: 'Login failed' }); }
  });

  app.post('/auth/forgot-password', async (req, res) => {
    const email = String(req.body.email || '').toLowerCase().trim();
    const user = await User.findOne({ email });
    if (user?.passwordHash) {
      const raw = token(); user.passwordReset = { tokenHash: hashToken(raw), expiresAt: new Date(Date.now() + 30 * 60 * 1000) }; await user.save();
      const url = `${process.env.APP_URL || 'http://localhost:3000'}/reset-password?token=${encodeURIComponent(raw)}`;
      await sendMail(email, 'Reset your CRYSTAL password', `Reset your password: ${url}\n\nThis link expires in 30 minutes and can only be used once.`);
      await audit(req, 'password_reset_requested', user);
    }
    res.json({ ok: true, message: 'If an account exists, a password reset link has been sent.' });
  });

  app.post('/auth/reset-password', async (req, res) => {
    try {
      const raw = String(req.body.token || ''); const password = String(req.body.password || '');
      if (password.length < 12 || password.length > 128) return res.status(400).json({ error: 'Password must be between 12 and 128 characters' });
      const user = await User.findOne({ 'passwordReset.tokenHash': hashToken(raw), 'passwordReset.expiresAt': { $gt: new Date() } });
      if (!user) return res.status(400).json({ error: 'Reset link is invalid or expired' });
      user.passwordHash = await argon2.hash(password, { type: argon2.argon2id }); user.passwordReset = undefined; await user.save();
      await audit(req, 'password_reset_completed', user);
      res.json({ ok: true });
    } catch { res.status(400).json({ error: 'Password reset failed' }); }
  });

  app.post('/auth/change-password', async (req, res) => {
    if (!req.user || req.session.mfaPending) return res.status(401).json({ error: 'Authentication required' });
    const current = String(req.body.currentPassword || ''); const next = String(req.body.newPassword || '');
    if (next.length < 12 || next.length > 128 || !(await argon2.verify(req.user.passwordHash || '', current).catch(() => false))) return res.status(400).json({ error: 'Unable to change password' });
    req.user.passwordHash = await argon2.hash(next, { type: argon2.argon2id }); await req.user.save();
    await audit(req, 'password_changed', req.user); res.json({ ok: true });
  });

  app.post('/auth/mfa/disable', async (req, res) => {
    if (!req.user || req.session.mfaPending || !req.user.mfa?.enabled) return res.status(401).json({ error: 'Authentication required' });
    const password = String(req.body.password || ''); const code = String(req.body.token || '').replace(/\s/g, '');
    const passOk = await argon2.verify(req.user.passwordHash || '', password).catch(() => false);
    const otpOk = req.user.mfa.secret && verifySync({ token: code, secret: decrypt(req.user.mfa.secret) }).valid;
    if (!passOk || !otpOk) return res.status(400).json({ error: 'Current password and authenticator code are required' });
    req.user.mfa = { enabled: false, secret: undefined, backupCodes: [] }; await req.user.save(); await audit(req, 'mfa_disabled', req.user); res.json({ ok: true });
  });

  app.post('/auth/mfa/recovery', async (req, res) => {
    if (!req.user || req.session.mfaPending || !req.user.mfa?.enabled) return res.status(401).json({ error: 'Authentication required' });
    const password = String(req.body.password || '');
    if (!(await argon2.verify(req.user.passwordHash || '', password).catch(() => false))) return res.status(400).json({ error: 'Invalid credentials' });
    const codes = Array.from({ length: 10 }, backupCode);
    req.user.mfa.backupCodes = await Promise.all(codes.map(c => argon2.hash(c))); await req.user.save(); await audit(req, 'mfa_recovery_codes_regenerated', req.user); res.json({ ok: true, recoveryCodes: codes });
  });

  app.post('/auth/mfa/verify', async (req, res) => {
    if (!req.user || !req.session.mfaPending) return res.json({ ok: true });
    const code = String(req.body.token || '').replace(/\s/g, '');
    let valid = false;
    if (req.user.mfa?.secret) valid = verifySync({ token: code, secret: decrypt(req.user.mfa.secret) }).valid;
    if (!valid) {
      for (let i = 0; i < (req.user.mfa?.backupCodes || []).length; i++) if (await argon2.verify(req.user.mfa.backupCodes[i], code).catch(() => false)) { req.user.mfa.backupCodes.splice(i, 1); await req.user.save(); valid = true; break; }
    }
    if (!valid) { await audit(req, 'mfa_failure', req.user); return res.status(401).json({ error: 'Invalid authentication code' }); }
    delete req.session.mfaPending; await audit(req, 'mfa_success', req.user); res.json({ ok: true });
  });

  app.post('/auth/logout', (req, res) => req.logout(async err => {
    if (err) return res.status(500).json({ error: 'Logout failed' });
    await audit(req, 'logout', null); req.session.destroy(() => res.json({ ok: true }));
  }));
};
