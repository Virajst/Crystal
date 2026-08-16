require('dotenv').config();
const crypto = require('crypto');
const path = require('path');
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const mongoose = require('mongoose');
const argon2 = require('argon2');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const MicrosoftStrategy = require('passport-microsoft-oauth2').Strategy;
const QRCode = require('qrcode');
const { generateSecret, generateURI, verifySync } = require('otplib');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const APP_URL = process.env.APP_URL || `http://localhost:${PORT}`;

if (!process.env.SESSION_SECRET || !process.env.MONGODB_URI) {
  throw new Error('SESSION_SECRET and MONGODB_URI are required');
}

mongoose.connect(process.env.MONGODB_URI);

const userSchema = new mongoose.Schema({
  email: { type: String, lowercase: true, trim: true, index: true },
  name: { type: String, trim: true },
  passwordHash: String,
  providers: [{ name: String, id: String }],
  avatarUrl: String,
  mfa: {
    enabled: { type: Boolean, default: false },
    secret: String,
    backupCodes: [String]
  }
}, { timestamps: true });
const User = mongoose.model('User', userSchema);

function encryptionKey() {
  const raw = Buffer.from(process.env.TOTP_ENCRYPTION_KEY || '', 'base64');
  if (raw.length !== 32) throw new Error('TOTP_ENCRYPTION_KEY must be a base64-encoded 32-byte key');
  return raw;
}
function encrypt(value) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey(), iv);
  const encrypted = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
  return [iv, cipher.getAuthTag(), encrypted].map(x => x.toString('base64')).join('.');
}
function decrypt(value) {
  const [ivB64, tagB64, dataB64] = value.split('.');
  const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey(), Buffer.from(ivB64, 'base64'));
  decipher.setAuthTag(Buffer.from(tagB64, 'base64'));
  return Buffer.concat([decipher.update(Buffer.from(dataB64, 'base64')), decipher.final()]).toString('utf8');
}
function randomBackupCode() { return crypto.randomBytes(8).toString('hex').toUpperCase(); }

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try { done(null, await User.findById(id)); } catch (e) { done(e); }
});

async function upsertOAuth(profile, provider) {
  const providerId = profile.id;
  let user = await User.findOne({ providers: { $elemMatch: { name: provider, id: providerId } } });
  const email = profile.emails?.[0]?.value?.toLowerCase();
  if (!user && email) user = await User.findOne({ email });
  if (!user) user = new User({ email, name: profile.displayName || email || providerId });
  if (!user.providers.some(p => p.name === provider && p.id === providerId)) user.providers.push({ name: provider, id: providerId });
  if (profile.photos?.[0]?.value) user.avatarUrl = profile.photos[0].value;
  await user.save();
  return user;
}

if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL || `${APP_URL}/auth/google/callback`
  }, async (_access, _refresh, profile, done) => {
    try { done(null, await upsertOAuth(profile, 'google')); } catch (e) { done(e); }
  }));
}
if (process.env.MICROSOFT_CLIENT_ID && process.env.MICROSOFT_CLIENT_SECRET) {
  passport.use(new MicrosoftStrategy({
    clientID: process.env.MICROSOFT_CLIENT_ID,
    clientSecret: process.env.MICROSOFT_CLIENT_SECRET,
    callbackURL: process.env.MICROSOFT_CALLBACK_URL || `${APP_URL}/auth/microsoft/callback`,
    scope: ['user.read']
  }, async (_access, _refresh, profile, done) => {
    try { done(null, await upsertOAuth(profile, 'microsoft')); } catch (e) { done(e); }
  }));
}

app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: process.env.MONGODB_URI }),
  cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 1000 * 60 * 60 * 24 * 7 }
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.static(path.join(__dirname, '../public')));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 20, standardHeaders: 'draft-8', legacyHeaders: false });
app.use('/auth/login', authLimiter);
app.use('/auth/register', authLimiter);
app.use('/auth/mfa', authLimiter);

function requireAuth(req, res, next) { if (!req.user) return res.status(401).json({ error: 'Authentication required' }); next(); }
function requireFullAuth(req, res, next) { if (!req.user || req.session.mfaPending) return res.status(401).json({ error: 'Full authentication required' }); next(); }

app.get('/api/me', (req, res) => {
  if (!req.user) return res.json({ authenticated: false });
  res.json({ authenticated: true, user: { id: req.user.id, email: req.user.email, name: req.user.name, avatarUrl: req.user.avatarUrl, mfaEnabled: !!req.user.mfa?.enabled }, mfaPending: !!req.session.mfaPending });
});

app.post('/auth/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    if (!email || !password || password.length < 12) return res.status(400).json({ error: 'Email and a password of at least 12 characters are required' });
    const normalized = email.toLowerCase().trim();
    if (await User.exists({ email: normalized })) return res.status(409).json({ error: 'Account already exists' });
    const user = await User.create({ email: normalized, name: name?.trim() || normalized, passwordHash: await argon2.hash(password, { type: argon2.argon2id }) });
    req.login(user, err => err ? res.status(500).json({ error: 'Could not create session' }) : res.status(201).json({ ok: true }));
  } catch (e) { console.error(e); res.status(500).json({ error: 'Registration failed' }); }
});

app.post('/auth/login', async (req, res) => {
  try {
    const user = await User.findOne({ email: String(req.body.email || '').toLowerCase().trim() });
    if (!user?.passwordHash || !(await argon2.verify(user.passwordHash, String(req.body.password || '')))) return res.status(401).json({ error: 'Invalid email or password' });
    req.login(user, err => {
      if (err) return res.status(500).json({ error: 'Login failed' });
      if (user.mfa?.enabled) req.session.mfaPending = true;
      res.json({ ok: true, mfaRequired: !!user.mfa?.enabled });
    });
  } catch (e) { res.status(500).json({ error: 'Login failed' }); }
});

app.get('/auth/google', (req, res, next) => {
  if (!process.env.GOOGLE_CLIENT_ID) return res.status(503).json({ error: 'Google authentication is not configured' });
  passport.authenticate('google', { scope: ['openid', 'profile', 'email'] })(req, res, next);
});
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/?error=google' }), (req, res) => res.redirect('/'));
app.get('/auth/microsoft', (req, res, next) => {
  if (!process.env.MICROSOFT_CLIENT_ID) return res.status(503).json({ error: 'Microsoft authentication is not configured' });
  passport.authenticate('microsoft')(req, res, next);
});
app.get('/auth/microsoft/callback', passport.authenticate('microsoft', { failureRedirect: '/?error=microsoft' }), (req, res) => res.redirect('/'));

app.post('/auth/mfa/verify', requireAuth, async (req, res) => {
  try {
    if (!req.session.mfaPending) return res.json({ ok: true });
    const token = String(req.body.token || '').replace(/\s/g, '');
    let valid = false;
    if (req.user.mfa?.secret) valid = verifySync({ token, secret: decrypt(req.user.mfa.secret) }).valid;
    if (!valid && Array.isArray(req.user.mfa?.backupCodes)) {
      for (let i = 0; i < req.user.mfa.backupCodes.length; i++) {
        if (await argon2.verify(req.user.mfa.backupCodes[i], token).catch(() => false)) {
          req.user.mfa.backupCodes.splice(i, 1); await req.user.save(); valid = true; break;
        }
      }
    }
    if (!valid) return res.status(401).json({ error: 'Invalid authentication code' });
    delete req.session.mfaPending;
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: 'Invalid authentication code' }); }
});

app.post('/auth/mfa/setup', requireFullAuth, async (req, res) => {
  try {
    const secret = generateSecret();
    req.session.mfaSetupSecret = secret;
    const uri = generateURI({ issuer: 'CRYSTAL', label: req.user.email, secret });
    res.json({ secret, qrCode: await QRCode.toDataURL(uri), uri });
  } catch (e) { res.status(500).json({ error: 'Could not create MFA setup' }); }
});

app.post('/auth/mfa/enable', requireFullAuth, async (req, res) => {
  try {
    const secret = req.session.mfaSetupSecret;
    if (!secret) return res.status(400).json({ error: 'Start MFA setup first' });
    if (!verifySync({ token: String(req.body.token || ''), secret }).valid) return res.status(400).json({ error: 'Invalid code' });
    const backupCodes = Array.from({ length: 10 }, randomBackupCode);
    req.user.mfa = { enabled: true, secret: encrypt(secret), backupCodes: await Promise.all(backupCodes.map(c => argon2.hash(c))) };
    await req.user.save();
    delete req.session.mfaSetupSecret;
    res.json({ ok: true, backupCodes });
  } catch (e) { res.status(500).json({ error: 'Could not enable MFA' }); }
});

app.post('/auth/logout', (req, res) => req.logout(err => { if (err) return res.status(500).json({ error: 'Logout failed' }); req.session.destroy(() => res.json({ ok: true })); }));
app.get('/api/protected', requireFullAuth, (req, res) => res.json({ ok: true, message: 'Protected CRYSTAL resource', userId: req.user.id }));

app.use((err, _req, res, _next) => { console.error(err); res.status(500).json({ error: 'Internal server error' }); });
app.listen(PORT, () => console.log(`CRYSTAL auth running at ${APP_URL}`));
