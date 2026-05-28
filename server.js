const express = require('express');
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const nodemailer = require('nodemailer');
const { body, validationResult } = require('express-validator');

const app = express();
const PORT = process.env.PORT || 3000;
const APP_URL = process.env.APP_URL || 'https://smintern.com';
const TRUST_PROXY = process.env.TRUST_PROXY === '1';

if (TRUST_PROXY) {
  app.set('trust proxy', 1);
}

// General rate limiter (basic protection)
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200, // limit each IP to 200 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false
});

app.use(generalLimiter);
app.use(helmet());
app.use(cors({
  origin: function (origin, callback) {
    if (!origin || origin === APP_URL) return callback(null, true);
    return callback(new Error('Not allowed by CORS'));
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type'],
  credentials: true
}));
app.use(bodyParser.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

// Session setup
app.use(session({
  name: 'smintern_session',
  secret: process.env.SESSION_SECRET || 'smintern-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 2 * 60 * 60 * 1000
  }
}));

// Simple auth configuration (change in production)
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'smintern';
const RECAPTCHA_SITE_KEY = process.env.RECAPTCHA_SITE_KEY || '';
const RECAPTCHA_SECRET_KEY = process.env.RECAPTCHA_SECRET_KEY || '';
const EMAIL_HOST = process.env.EMAIL_HOST || '';
const EMAIL_PORT = Number(process.env.EMAIL_PORT || '587');
const EMAIL_USER = process.env.EMAIL_USER || '';
const EMAIL_PASS = process.env.EMAIL_PASS || '';
const EMAIL_FROM = process.env.EMAIL_FROM || 'no-reply@smintern.com';

// Rate limiters for specific endpoints
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit to 5 login attempts per IP
  message: { error: 'Too many login attempts, try again later.' },
  standardHeaders: true,
  legacyHeaders: false
});

const applyLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 30, // limit to 30 submissions per IP per hour
  message: { error: 'Too many submissions, try again later.' },
  standardHeaders: true,
  legacyHeaders: false
});

const LOCKOUT_THRESHOLD = 5;
const LOCKOUT_WINDOW_MS = 15 * 60 * 1000; // 15 minutes

const crypto = require('crypto');
const { promisify } = require('util');
const pbkdf2Async = promisify(crypto.pbkdf2);
const HASH_ITERATIONS = 120000;
const HASH_KEYLEN = 64;

const DATA_DIR = path.join(__dirname, 'data');
const UPLOADS_DIR = path.join(__dirname, 'uploads');
const LOCKOUT_FILE = path.join(DATA_DIR, 'login-lockouts.json');
const APPLICATIONS_FILE = path.join(DATA_DIR, 'applications.json');
const POSITIONS_FILE = path.join(DATA_DIR, 'positions.json');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const PROFILES_FILE = path.join(DATA_DIR, 'user-profiles.json');
const CV_UPLOADS_FILE = path.join(DATA_DIR, 'cv-uploads.json');
const RESET_TOKENS_FILE = path.join(DATA_DIR, 'reset-tokens.json');
const DELETE_TOKENS_FILE = path.join(DATA_DIR, 'delete-tokens.json');
const allowedOrigins = [APP_URL, 'http://localhost:3000', 'https://localhost:3000'];

const upload = multer({
  dest: UPLOADS_DIR,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowedMimeTypes = [
      'application/pdf',
      'application/msword',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    ];
    if (!allowedMimeTypes.includes(file.mimetype)) {
      return cb(new Error('invalid_file_type'));
    }
    cb(null, true);
  }
});

function validateInput(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      error: 'invalid_input',
      details: errors.array().map(e => e.msg)
    });
  }
  next();
}

function enforceSameOrigin(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }

  const originHeader = req.get('Origin') || req.get('Referer');
  if (!originHeader) {
    return next();
  }

  try {
    const parsedOrigin = new URL(originHeader).origin;
    if (!allowedOrigins.includes(parsedOrigin)) {
      return res.status(403).json({ success: false, error: 'invalid_origin' });
    }
  } catch (err) {
    return res.status(403).json({ success: false, error: 'invalid_origin' });
  }

  next();
}

app.use(enforceSameOrigin);

function loadLockouts() {
  try {
    const raw = fs.readFileSync(LOCKOUT_FILE, 'utf8');
    return JSON.parse(raw || '{}');
  } catch (err) {
    return {};
  }
}

function saveLockouts(data) {
  fs.writeFileSync(LOCKOUT_FILE, JSON.stringify(data, null, 2), 'utf8');
}

function readPositions() {
  try {
    const raw = fs.readFileSync(POSITIONS_FILE, 'utf8');
    return JSON.parse(raw || '[]');
  } catch (err) {
    return [];
  }
}

function savePositions(data) {
  fs.writeFileSync(POSITIONS_FILE, JSON.stringify(data, null, 2), 'utf8');
}

function loadUsers() {
  try {
    const raw = fs.readFileSync(USERS_FILE, 'utf8');
    return JSON.parse(raw || '{}');
  } catch (err) {
    return {};
  }
}

function saveUsers(data) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(data, null, 2), 'utf8');
}

function findUserByUsernameOrEmail(query) {
  const users = loadUsers();
  return Object.values(users).find(u => u.username === query || (u.email && u.email.toLowerCase() === query.toLowerCase()));
}

function createTokenRecord(username, action) {
  return {
    token: crypto.randomBytes(20).toString('hex'),
    username,
    action,
    expiresAt: Date.now() + 1000 * 60 * 60 // 1 hour
  };
}

function cleanExpiredTokens(tokens) {
  return tokens.filter(token => token.expiresAt > Date.now());
}

function loadTokens(filePath) {
  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    return JSON.parse(raw || '[]');
  } catch (err) {
    return [];
  }
}

function saveTokens(filePath, tokens) {
  fs.writeFileSync(filePath, JSON.stringify(tokens, null, 2), 'utf8');
}

async function sendEmail(to, subject, text, html) {
  if (EMAIL_HOST && EMAIL_USER && EMAIL_PASS) {
    const transporter = nodemailer.createTransport({
      host: EMAIL_HOST,
      port: EMAIL_PORT,
      secure: EMAIL_PORT === 465,
      auth: { user: EMAIL_USER, pass: EMAIL_PASS }
    });
    await transporter.sendMail({ from: EMAIL_FROM, to, subject, text, html });
  } else {
    console.log('EMAIL NOT CONFIGURED. Email to:', to);
    console.log('Subject:', subject);
    console.log('Text:', text);
    if (html) console.log('HTML:', html);
  }
}

async function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = await pbkdf2Async(password, salt, HASH_ITERATIONS, HASH_KEYLEN, 'sha256');
  return `${HASH_ITERATIONS}:${salt}:${derived.toString('hex')}`;
}

async function verifyPassword(password, storedHash) {
  const [iterations, salt, key] = storedHash.split(':');
  const derived = await pbkdf2Async(password, salt, Number(iterations), HASH_KEYLEN, 'sha256');
  return derived.toString('hex') === key;
}

function loadProfiles() {
  try {
    const raw = fs.readFileSync(PROFILES_FILE, 'utf8');
    return JSON.parse(raw || '{}');
  } catch (err) {
    return {};
  }
}

function saveProfiles(data) {
  fs.writeFileSync(PROFILES_FILE, JSON.stringify(data, null, 2), 'utf8');
}

function loadCvUploads() {
  try {
    const raw = fs.readFileSync(CV_UPLOADS_FILE, 'utf8');
    return JSON.parse(raw || '[]');
  } catch (err) {
    return [];
  }
}

function saveCvUploads(data) {
  fs.writeFileSync(CV_UPLOADS_FILE, JSON.stringify(data, null, 2), 'utf8');
}

let loginAttempts = loadLockouts();

function getClientKey(req) {
  return req.ip || req.connection.remoteAddress || 'unknown';
}

function isLocked(key) {
  const data = loginAttempts[key];
  return data && data.lockUntil && data.lockUntil > Date.now();
}

function recordFailedLogin(key) {
  const data = loginAttempts[key] || { count: 0, lockUntil: 0 };
  data.count += 1;
  if (data.count >= LOCKOUT_THRESHOLD) {
    data.lockUntil = Date.now() + LOCKOUT_WINDOW_MS;
  }
  loginAttempts[key] = data;
  saveLockouts(loginAttempts);
}

function resetLoginAttempts(key) {
  delete loginAttempts[key];
  saveLockouts(loginAttempts);
}

async function verifyRecaptcha(token, ip) {
  if (!RECAPTCHA_SECRET_KEY) return true;
  if (!token) return false;
  try {
    const params = new URLSearchParams();
    params.append('secret', RECAPTCHA_SECRET_KEY);
    params.append('response', token);
    if (ip) params.append('remoteip', ip);
    const r = await fetch('https://www.google.com/recaptcha/api/siteverify', {
      method: 'POST',
      body: params
    });
    const result = await r.json();
    return result.success && (!('score' in result) || result.score >= 0.5);
  } catch (err) {
    console.error('reCAPTCHA verify failed', err);
    return false;
  }
}

app.get('/recaptcha-config', (req, res) => {
  res.json({ siteKey: RECAPTCHA_SITE_KEY });
});

app.get('/api/positions', (req, res) => {
  try {
    const positions = readPositions();
    res.json(positions);
  } catch (err) {
    console.error('Failed to read positions', err);
    res.status(500).json({ success: false, error: 'read_failed' });
  }
});

function requireUserAuth(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ success: false, error: 'unauthorized' });
  }
  next();
}

function requireAdmin(req, res, next) {
  if (req.session.user !== ADMIN_USER) {
    return res.status(403).json({ success: false, error: 'forbidden' });
  }
  next();
}

app.get('/api/admin/positions', requireAdmin, (req, res) => {
  try {
    const positions = readPositions();
    res.json(positions.reverse());
  } catch (err) {
    console.error('Failed to read admin positions', err);
    res.status(500).json({ success: false, error: 'read_failed' });
  }
});

app.post('/api/admin/positions', requireAdmin, (req, res) => {
  const { title, company, city, subject, desc, logoUrl, location } = req.body || {};
  if (!title || !company || !city || !subject || !desc) {
    return res.status(400).json({ success: false, error: 'missing_fields' });
  }
  try {
    const positions = readPositions();
    const newPosition = {
      id: Date.now(),
      title: title.trim(),
      company: company.trim(),
      city: city.trim(),
      location: location ? location.trim() : city.trim(),
      subject: subject.trim(),
      desc: desc.trim(),
      logoUrl: logoUrl ? logoUrl.trim() : '',
      createdAt: new Date().toISOString()
    };
    positions.push(newPosition);
    savePositions(positions);
    res.status(201).json({ success: true, position: newPosition });
  } catch (err) {
    console.error('Failed to save position', err);
    res.status(500).json({ success: false, error: 'save_failed' });
  }
});

app.delete('/api/admin/positions/:id', requireAdmin, (req, res) => {
  try {
    const positions = readPositions();
    const id = Number(req.params.id);
    const filtered = positions.filter(p => p.id !== id);
    if (filtered.length === positions.length) {
      return res.status(404).json({ success: false, error: 'not_found' });
    }
    savePositions(filtered);
    res.json({ success: true, id });
  } catch (err) {
    console.error('Failed to delete position', err);
    res.status(500).json({ success: false, error: 'delete_failed' });
  }
});

// Login endpoint (rate-limited)
app.post('/login', loginLimiter,
  body('username').trim().notEmpty().withMessage('missing_username'),
  body('password').notEmpty().withMessage('missing_password'),
  body('recaptchaToken').optional().isString(),
  body('hp').optional().isEmpty().withMessage('bot_detected'),
  validateInput,
  async (req, res) => {
    const ipKey = getClientKey(req);
    if (isLocked(ipKey)) {
      const data = loginAttempts[ipKey];
      const retryAfter = Math.ceil((data.lockUntil - Date.now()) / 1000);
      return res.status(429).json({ success: false, error: 'locked_out', retryAfter });
    }

    const { username, password, recaptchaToken } = req.body || {};
    if (!(await verifyRecaptcha(recaptchaToken, req.ip))) {
      return res.status(400).json({ success: false, error: 'recaptcha_failed' });
    }

    if (username === ADMIN_USER) {
      if (password === ADMIN_PASS) {
        resetLoginAttempts(ipKey);
        req.session.user = username;
        return res.json({ success: true, role: 'admin' });
      }
      recordFailedLogin(ipKey);
      return res.status(401).json({ success: false, error: 'invalid_credentials' });
    }

    const users = loadUsers();
    const account = users[username];
    if (!account) {
      recordFailedLogin(ipKey);
      return res.status(401).json({ success: false, error: 'invalid_credentials' });
    }

    if (!(await verifyPassword(password, account.passwordHash))) {
      recordFailedLogin(ipKey);
      return res.status(401).json({ success: false, error: 'invalid_credentials' });
    }

    resetLoginAttempts(ipKey);
    req.session.user = username;
    res.json({ success: true, role: 'member' });
  }
);

app.post('/register', loginLimiter,
  body('username')
    .trim()
    .toLowerCase()
    .isLength({ min: 3, max: 25 })
    .matches(/^[a-z0-9_]+$/)
    .withMessage('invalid_username'),
  body('password').isLength({ min: 8 }).withMessage('password_too_short'),
  body('email').optional({ nullable: true, checkFalsy: true }).isEmail().normalizeEmail(),
  body('recoveryPhrase').trim().isLength({ min: 8 }).withMessage('recovery_phrase_too_short'),
  validateInput,
  async (req, res) => {
    const { username, password, email, recoveryPhrase } = req.body || {};

    if (username === ADMIN_USER) {
      return res.status(400).json({ success: false, error: 'invalid_username' });
    }

    const users = loadUsers();
    if (users[username]) {
      return res.status(409).json({ success: false, error: 'user_exists' });
    }

    const passwordHash = await hashPassword(password);
    const recoveryPhraseHash = await hashPassword(recoveryPhrase);
    users[username] = {
      username,
      passwordHash,
      recoveryPhraseHash,
      email: email || '',
      createdAt: new Date().toISOString()
    };
    saveUsers(users);
    req.session.user = username;
    res.json({ success: true, role: 'member' });
  }
);

app.post('/forgot', loginLimiter,
  body('username').trim().notEmpty().withMessage('missing_username'),
  body('recoveryPhrase').trim().notEmpty().withMessage('missing_recovery_phrase'),
  body('newPassword').isLength({ min: 8 }).withMessage('password_too_short'),
  validateInput,
  async (req, res) => {
    const { username, recoveryPhrase, newPassword } = req.body || {};
    const users = loadUsers();
    const account = users[username];
    if (!account || !account.recoveryPhraseHash) {
      return res.status(401).json({ success: false, error: 'invalid_recovery' });
    }

    if (!(await verifyPassword(recoveryPhrase, account.recoveryPhraseHash))) {
      return res.status(401).json({ success: false, error: 'invalid_recovery' });
    }

    account.passwordHash = await hashPassword(newPassword);
    saveUsers(users);
    res.json({ success: true });
  }
);

app.post('/forgot/request', loginLimiter,
  body('usernameOrEmail').trim().notEmpty().withMessage('missing_fields'),
  validateInput,
  async (req, res) => {
    const { usernameOrEmail } = req.body || {};
    const user = findUserByUsernameOrEmail(usernameOrEmail.trim());
    if (!user || !user.email) {
      return res.status(200).json({ success: true });
    }

    const tokens = cleanExpiredTokens(loadTokens(RESET_TOKENS_FILE));
    const tokenRecord = createTokenRecord(user.username, 'password_reset');
    tokens.push(tokenRecord);
    saveTokens(RESET_TOKENS_FILE, tokens);

    const resetUrl = `${APP_URL}/reset-password.html?token=${tokenRecord.token}`;
    await sendEmail(user.email, 'Password Reset for SMintern', `Reset your password: ${resetUrl}`, `<p>Reset your password with this link:</p><p><a href="${resetUrl}">${resetUrl}</a></p>`);
    res.json({ success: true });
  }
);

app.post('/reset-password', loginLimiter,
  body('token').trim().isHexadecimal().isLength({ min: 40 }).withMessage('invalid_token'),
  body('newPassword').isLength({ min: 8 }).withMessage('password_too_short'),
  validateInput,
  async (req, res) => {
    const { token, newPassword } = req.body || {};
    const tokens = cleanExpiredTokens(loadTokens(RESET_TOKENS_FILE));
    const record = tokens.find(item => item.token === token && item.action === 'password_reset');
    if (!record) {
      return res.status(400).json({ success: false, error: 'invalid_token' });
    }

    const users = loadUsers();
    const account = users[record.username];
    if (!account) {
      return res.status(404).json({ success: false, error: 'user_not_found' });
    }

    account.passwordHash = await hashPassword(newPassword);
    saveUsers(users);

    const updatedTokens = tokens.filter(item => item.token !== token);
    saveTokens(RESET_TOKENS_FILE, updatedTokens);

    res.json({ success: true });
  }
);

app.post('/account/delete/request', requireUserAuth, async (req, res) => {
  const users = loadUsers();
  const account = users[req.session.user];
  if (!account || !account.email) {
    return res.status(400).json({ success: false, error: 'email_not_found' });
  }

  const tokens = cleanExpiredTokens(loadTokens(DELETE_TOKENS_FILE));
  const tokenRecord = createTokenRecord(req.session.user, 'delete_account');
  tokens.push(tokenRecord);
  saveTokens(DELETE_TOKENS_FILE, tokens);

  const deleteUrl = `${APP_URL}/delete-account.html?token=${tokenRecord.token}`;
  await sendEmail(account.email, 'Account Deletion Confirmation for SMintern', `Confirm account deletion: ${deleteUrl}`, `<p>Confirm deletion with this link:</p><p><a href="${deleteUrl}">${deleteUrl}</a></p>`);
  res.json({ success: true });
});

app.post('/account/delete/confirm', async (req, res) => {
  const { token } = req.body || {};
  if (!token) {
    return res.status(400).json({ success: false, error: 'missing_token' });
  }

  const tokens = cleanExpiredTokens(loadTokens(DELETE_TOKENS_FILE));
  const record = tokens.find(item => item.token === token && item.action === 'delete_account');
  if (!record) {
    return res.status(400).json({ success: false, error: 'invalid_token' });
  }

  const users = loadUsers();
  const profiles = loadProfiles();
  const uploads = loadCvUploads();
  const account = users[record.username];
  if (!account) {
    return res.status(404).json({ success: false, error: 'user_not_found' });
  }

  delete users[record.username];
  delete profiles[record.username];
  const remainingUploads = uploads.filter(item => item.username !== record.username);
  saveUsers(users);
  saveProfiles(profiles);
  saveCvUploads(remainingUploads);

  const updatedTokens = tokens.filter(item => item.token !== token);
  saveTokens(DELETE_TOKENS_FILE, updatedTokens);

  res.json({ success: true });
});

app.post('/api/account/password', requireUserAuth,
  body('currentPassword').notEmpty().withMessage('missing_current_password'),
  body('newPassword').isLength({ min: 8 }).withMessage('password_too_short'),
  validateInput,
  async (req, res) => {
    const { currentPassword, newPassword } = req.body || {};
    const users = loadUsers();
    const account = users[req.session.user];
    if (!account) {
      return res.status(404).json({ success: false, error: 'user_not_found' });
    }

    if (!(await verifyPassword(currentPassword, account.passwordHash))) {
      return res.status(401).json({ success: false, error: 'invalid_current_password' });
    }

    account.passwordHash = await hashPassword(newPassword);
    saveUsers(users);
    res.json({ success: true });
  }
);

app.post('/api/account/delete', requireUserAuth,
  body('password').notEmpty().withMessage('missing_password'),
  validateInput,
  async (req, res) => {
    const { password } = req.body || {};
    const users = loadUsers();
    const profiles = loadProfiles();
    const uploads = loadCvUploads();
    const account = users[req.session.user];
    if (!account || !(await verifyPassword(password, account.passwordHash))) {
      return res.status(401).json({ success: false, error: 'invalid_password' });
    }

    delete users[req.session.user];
    delete profiles[req.session.user];
    const remainingUploads = uploads.filter(item => item.owner !== req.session.user);
    saveUsers(users);
    saveProfiles(profiles);
    saveCvUploads(remainingUploads);
    req.session.destroy(() => {
      res.json({ success: true });
    });
  }
);

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

app.get('/api/profile', requireUserAuth, (req, res) => {
  const profiles = loadProfiles();
  const uploads = loadCvUploads().filter(item => item.owner === req.session.user);
  const profile = profiles[req.session.user] || { fullName: '', email: '', headline: '', bio: '' };
  res.json({
    username: req.session.user,
    role: req.session.user === ADMIN_USER ? 'admin' : 'member',
    profile,
    uploads
  });
});

app.post('/api/profile', requireUserAuth,
  body('fullName').trim().isLength({ max: 100 }).escape().optional({ nullable: true, checkFalsy: true }),
  body('email').optional({ nullable: true, checkFalsy: true }).isEmail().normalizeEmail(),
  body('headline').trim().isLength({ max: 100 }).escape().optional({ nullable: true, checkFalsy: true }),
  body('bio').trim().isLength({ max: 500 }).escape().optional({ nullable: true, checkFalsy: true }),
  validateInput,
  (req, res) => {
    const { fullName, email, headline, bio } = req.body || {};
    const profiles = loadProfiles();
    profiles[req.session.user] = {
      fullName: fullName || '',
      email: email || '',
      headline: headline || '',
      bio: bio || ''
    };
    saveProfiles(profiles);
    res.json({ success: true });
  }
);

app.post('/api/profile/cv', requireUserAuth, upload.single('cv'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ success: false, error: 'missing_file' });
  }
  const uploads = loadCvUploads();
  uploads.push({
    owner: req.session.user,
    fileName: path.basename(req.file.originalname),
    path: `/uploads/${req.file.filename}`,
    uploadedAt: new Date().toISOString()
  });
  saveCvUploads(uploads);
  res.json({ success: true });
});

// Serve admin page only when authenticated
app.get('/admin.html', (req, res, next) => {
  if (!req.session.user) return res.redirect('/login.html');
  if (req.session.user !== ADMIN_USER) return res.redirect('/profile.html');
  res.sendFile(path.join(__dirname, 'admin.html'));
});

app.get('/profile.html', (req, res, next) => {
  if (!req.session.user) return res.redirect('/login.html');
  res.sendFile(path.join(__dirname, 'profile.html'));
});

app.get('/register', (req, res) => {
  if (req.session.user) {
    return req.session.user === ADMIN_USER ? res.redirect('/admin.html') : res.redirect('/profile.html');
  }
  res.redirect('/register.html');
});

app.get('/register.html', (req, res) => {
  if (req.session.user) {
    return req.session.user === ADMIN_USER ? res.redirect('/admin.html') : res.redirect('/profile.html');
  }
  res.sendFile(path.join(__dirname, 'register.html'));
});

// Login page redirect guard: if already authenticated, go to the right dashboard
app.get('/login', (req, res) => {
  if (req.session.user) {
    return req.session.user === ADMIN_USER ? res.redirect('/admin.html') : res.redirect('/profile.html');
  }
  res.redirect('/login.html');
});
app.get('/login.html', (req, res) => {
  if (req.session.user) {
    return req.session.user === ADMIN_USER ? res.redirect('/admin.html') : res.redirect('/profile.html');
  }
  res.sendFile(path.join(__dirname, 'login.html'));
});

// static files (serve other assets)
app.use(express.static(path.join(__dirname)));

app.use((err, req, res, next) => {
  if (!err) return next();
  console.error('Server error:', err);
  if (err.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json({ success: false, error: 'file_too_large' });
  }
  if (err.message === 'invalid_file_type') {
    return res.status(400).json({ success: false, error: 'invalid_file_type' });
  }
  if (err instanceof SyntaxError) {
    return res.status(400).json({ success: false, error: 'invalid_json' });
  }
  res.status(500).json({ success: false, error: 'server_error' });
});

// ensure data dir and files exist
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR);
if (!fs.existsSync(LOCKOUT_FILE)) fs.writeFileSync(LOCKOUT_FILE, '{}', 'utf8');
if (!fs.existsSync(APPLICATIONS_FILE)) fs.writeFileSync(APPLICATIONS_FILE, '[]', 'utf8');
if (!fs.existsSync(POSITIONS_FILE)) fs.writeFileSync(POSITIONS_FILE, '[]', 'utf8');
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, '{}', 'utf8');
if (!fs.existsSync(PROFILES_FILE)) fs.writeFileSync(PROFILES_FILE, '{}', 'utf8');
if (!fs.existsSync(CV_UPLOADS_FILE)) fs.writeFileSync(CV_UPLOADS_FILE, '[]', 'utf8');

app.post('/apply', applyLimiter, (req, res) => {
  try {
    const application = {
      id: Date.now(),
      submittedAt: new Date().toISOString(),
      ...req.body
    };
    const raw = fs.readFileSync(APPLICATIONS_FILE, 'utf8');
    const arr = JSON.parse(raw || '[]');
    arr.push(application);
    fs.writeFileSync(APPLICATIONS_FILE, JSON.stringify(arr, null, 2), 'utf8');
    res.status(201).json({ success: true, id: application.id });
  } catch (err) {
    console.error('Failed to save application', err);
    res.status(500).json({ success: false, error: 'save_failed' });
  }
});

// Admin: return all applications (protected by session)
app.get('/applications', requireAdmin, (req, res) => {
  try {
    const raw = fs.readFileSync(APPLICATIONS_FILE, 'utf8') || '[]';
    const arr = JSON.parse(raw);
    res.json(arr.reverse()); // newest first
  } catch (err) {
    console.error('Failed to read applications', err);
    res.status(500).json({ success: false, error: 'read_failed' });
  }
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
