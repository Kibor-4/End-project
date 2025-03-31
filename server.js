const express = require('express');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const path = require('path');
const cors = require('cors');
const getPool = require('./database/db');
const helmet = require('helmet');
const { v4: uuidv4 } = require('uuid');
const rateLimit = require('express-rate-limit');
const winston = require('winston');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const cookieParser = require('cookie-parser');
require('dotenv').config();

const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
    transports: [new winston.transports.File({ filename: 'error.log', level: 'error' }), new winston.transports.File({ filename: 'combined.log' })]
});

if (process.env.NODE_ENV !== 'production') logger.add(new winston.transports.Console({ format: winston.format.simple() }));

const app = express();

['DB_HOST', 'DB_USER', 'DB_PASSWORD', 'DB_NAME', 'SESSION_SECRET'].forEach(envVar => {
    if (!process.env[envVar]) {
        logger.error(`Missing required environment variable: ${envVar}`);
        process.exit(1);
    }
});

app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100, message: 'Too many requests, try later.' }));
app.use(cookieParser());

app.use(async (req, res, next) => {
    try {
        await (await getPool).query('SELECT 1');
        next();
    } catch (err) {
        logger.error(`DB error: ${err.message}`);
        res.status(503).render('error', { message: 'Service unavailable', statusCode: 503, user: null });
    }
});

app.use(session({
    store: new MySQLStore({
        host: process.env.DB_HOST, port: process.env.DB_PORT || 3306, user: process.env.DB_USER, password: process.env.DB_PASSWORD, database: process.env.DB_NAME,
        createDatabaseTable: true, schema: { tableName: 'user_sessions', columnNames: { session_id: 'session_id', expires: 'expires', data: 'data' } },
        clearExpired: true, checkExpirationInterval: 900000, expiration: 86400000, connectionLimit: 10, retries: 3, onError: err => logger.error(`Session error: ${err.message}`)
    }),
    name: 'sessionId', secret: process.env.SESSION_SECRET || require('crypto').randomBytes(64).toString('hex'), resave: false, saveUninitialized: false, rolling: true,
    cookie: { httpOnly: true, secure: process.env.NODE_ENV === 'production', maxAge: 86400000, sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax', domain: process.env.COOKIE_DOMAIN || undefined },
    genid: uuidv4
}));

passport.use(new LocalStrategy({ usernameField: 'email', passwordField: 'password' }, async (email, password, done) => {
    try {
        const [users] = await (await getPool).query('SELECT * FROM Users WHERE email = ?', [email]);
        if (users.length === 0 || password !== users[0].password) return done(null, false, { message: users.length === 0 ? 'Incorrect email.' : 'Incorrect password.' });
        done(null, users[0]);
    } catch (err) { done(err); }
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
    try { done(null, (await (await getPool).query('SELECT id, email,Username, role FROM Users WHERE id = ?', [id]))[0][0]); } catch (err) { done(err); }
});

app.use(passport.initialize());
app.use(passport.session());
app.use((req, res, next) => {
    req.requestId = uuidv4();
    logger.info('Request', { requestId: req.requestId, timestamp: new Date().toISOString(), method: req.method, url: req.originalUrl, ip: req.ip, sessionId: req.sessionID || 'none', userAgent: req.get('User-Agent') });
    console.log(`[${req.requestId}] Session Debug -`, { sessionId: req.sessionID, authenticated: req.isAuthenticated(), user: req.user || 'Not authenticated' });
    res.locals.user = req.user || null;
    res.locals.isAuthenticated = req.isAuthenticated();
    next();
});

app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], scriptSrc: ["'self'", "'unsafe-inline'"], styleSrc: ["'self'", "'unsafe-inline'"], imgSrc: ["'self'", 'data:'] } }, hsts: { maxAge: 63072000, includeSubDomains: true, preload: true } }));
app.disable('x-powered-by');
app.use(cors({ origin: process.env.ALLOWED_ORIGINS?.split(',') || true, credentials: true, methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'] }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(express.json({ limit: '10kb' }));
app.set('view engine', 'ejs');
app.set('views', [path.join(__dirname, 'views/User'), path.join(__dirname, 'views/Admin'), path.join(__dirname, 'views/Shared')]);
app.use('/Public', express.static(path.join(__dirname, 'Public'), { maxAge: process.env.NODE_ENV === 'production' ? '1y' : 0, setHeaders: (res, path) => { if (path.endsWith('.css')) res.setHeader('Content-Type', 'text/css'); } }));
app.use('/login', (req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });

app.get('/health', (req, res) => res.status(200).json({ status: 'ok', timestamp: new Date().toISOString(), uptime: process.uptime(), authenticated: req.isAuthenticated() }));
if (process.env.NODE_ENV !== 'production') app.get('/session-info', (req, res) => res.json({ sessionId: req.sessionID, session: req.session, user: req.user, authenticated: req.isAuthenticated() }));
app.get('/about', (req, res) => res.render('about', { user: req.session.user || null, currentUrl: req.originalUrl }));

// Routes that don't need authentication
app.use('/', require('./router/AuthRoutes/router'));
app.use('/', require('./router/UserRoutes/signup'));

// Authentication middleware (applied to routes that require authentication)
function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) return next();
    req.session.returnTo = req.originalUrl;
    res.redirect('/login');
}

function ensureAdmin(req, res, next) {
    if (req.isAuthenticated() && req.user.role === 'admin') return next();
    res.status(403).render('error', { message: 'Forbidden', statusCode: 403, user: res.locals.user });
}

app.use((req, res) => {
    logger.warn(`404: ${req.method} ${req.originalUrl}`);
    res.status(404).render('error', { message: 'Page not found', statusCode: 404, user: res.locals.user });
});

app.use((err, req, res, next) => {
    logger.error(`Error [${req.method} ${req.url}]: ${err.stack}`);
    res.status(err.statusCode || 500).render('error', { message: err.message || 'Error', statusCode: err.statusCode || 500, user: res.locals.user, requestId: process.env.NODE_ENV !== 'production' ? req.requestId : undefined });
});

async function startServer() {
    try {
        const pool = await getPool;
        await verifySchema(pool);
        await createDefaultAdmin(pool);
        app.listen(process.env.PORT || 8100, () => logger.info(`Server on port ${process.env.PORT || 8100}, env: ${process.env.NODE_ENV || 'dev'}`));
    } catch (err) { logger.error(`Server failed: ${err.message}`); process.exit(1); }
}

async function verifySchema(pool) {
    const requiredTables = ['Users', 'user_sessions', 'Properties'];
    for (const table of requiredTables) if ((await pool.query('SHOW TABLES LIKE ?', [table]))[0].length === 0) throw new Error(`Missing table: ${table}`);
}

async function createDefaultAdmin(pool) {
    try {
        const [users] = await pool.query('SELECT * FROM Users WHERE role = ?', ['admin']);
        if (users.length === 0 && process.env.DEFAULT_ADMIN_PASSWORD) await pool.query('INSERT INTO Users (email, password, name, role) VALUES (?, ?, ?, ?)', ['admin@example.com', process.env.DEFAULT_ADMIN_PASSWORD, 'Default Admin', 'admin']);
    } catch (err) { logger.warn(`Admin creation failed: ${err.message}`); }
}

startServer();