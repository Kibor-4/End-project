const express = require('express');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const path = require('path');
const cors = require('cors');
const db = require('./database/db');
const helmet = require('helmet');
const { v4: uuidv4 } = require('uuid');
const rateLimit = require('express-rate-limit');
const winston = require('winston');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const morgan = require('morgan');
const flash = require('connect-flash');
const csrf = require('csurf');
require('dotenv').config();

// Enhanced configuration with defaults
const config = {
    db: {
        host: process.env.DB_HOST,
        port: process.env.DB_PORT || 3306,
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        database: process.env.DB_NAME
    },
    session: {
        secret: process.env.SESSION_SECRET || require('crypto').randomBytes(64).toString('hex'),
        cookieDomain: process.env.COOKIE_DOMAIN || 'localhost',
        secure: process.env.NODE_ENV === 'production',
        name: 'sessionId',
        maxAge: 86400000 // 24 hours
    },
    security: {
        corsOrigins: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
        rateLimit: {
            windowMs: 15 * 60 * 1000, // 15 minutes
            max: 100
        }
    },
    admin: {
        email: process.env.DEFAULT_ADMIN_EMAIL || 'admin@example.com',
        password: process.env.DEFAULT_ADMIN_PASSWORD || 'admin123'
    }
};

// Validate required configuration
const requiredEnvVars = ['DB_HOST', 'DB_USER', 'DB_PASSWORD', 'DB_NAME'];
requiredEnvVars.forEach(envVar => {
    if (!process.env[envVar]) {
        throw new Error(`Missing required environment variable: ${envVar}`);
    }
});

// Enhanced logger setup
const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: winston.format.combine(
        winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        winston.format.errors({ stack: true }),
        winston.format.json()
    ),
    transports: [
        new winston.transports.File({ 
            filename: 'logs/error.log', 
            level: 'error',
            maxsize: 5242880 // 5MB
        }),
        new winston.transports.File({ 
            filename: 'logs/combined.log',
            maxsize: 5242880
        })
    ],
    exceptionHandlers: [
        new winston.transports.File({ filename: 'logs/exceptions.log' })
    ]
});

// Console logging in development
if (process.env.NODE_ENV !== 'production') {
    logger.add(new winston.transports.Console({
        format: winston.format.combine(
            winston.format.colorize(),
            winston.format.simple()
        )
    }));
}

const app = express();

// Generate request ID for tracing
app.use((req, res, next) => {
    req.id = uuidv4();
    next();
});

// Enhanced database middleware with connection retry
const MAX_DB_RETRIES = 3;
let dbPool;
app.use(async (req, res, next) => {
    if (!dbPool) {
        let retries = 0;
        let lastError;
        
        while (retries < MAX_DB_RETRIES) {
            try {
                dbPool = await db.pool;
                const conn = await dbPool.getConnection();
                conn.release();
                logger.info('Database pool initialized successfully');
                break;
            } catch (err) {
                lastError = err;
                retries++;
                logger.warn(`Database connection attempt ${retries} failed, retrying...`);
                await new Promise(resolve => setTimeout(resolve, 2000));
            }
        }

        if (!dbPool) {
            logger.error(`Failed to initialize database after ${MAX_DB_RETRIES} attempts`);
            return res.status(503).render('error', { 
                message: 'Service unavailable', 
                statusCode: 503, 
                user: null 
            });
        }
    }
    
    req.db = dbPool;
    next();
});

// Security middleware with enhanced CSP
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", 'cdnjs.cloudflare.com'],
            styleSrc: ["'self'", "'unsafe-inline'", 'cdnjs.cloudflare.com', 'fonts.googleapis.com'],
            fontSrc: ["'self'", 'fonts.gstatic.com'],
            imgSrc: ["'self'", 'data:', 'blob:'],
            connectSrc: ["'self'"],
            frameSrc: ["'self'"]
        }
    },
    hsts: {
        maxAge: 63072000, // 2 years
        includeSubDomains: true,
        preload: true
    },
    referrerPolicy: { policy: 'same-origin' }
}));

app.disable('x-powered-by');

// Rate limiting with different tiers
const apiLimiter = rateLimit({
    windowMs: config.security.rateLimit.windowMs,
    max: config.security.rateLimit.max,
    handler: (req, res) => {
        logger.warn(`Rate limit exceeded for IP: ${req.ip}`);
        res.status(429).json({
            error: 'Too many requests, please try again later.'
        });
    }
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 20,
    handler: (req, res) => {
        req.flash('error', 'Too many login attempts, please try again later.');
        res.redirect('/auth/login');
    }
});

// Apply rate limiting to API routes
app.use('/api', apiLimiter);

// Cookie parser with signed cookies
app.use(cookieParser(process.env.COOKIE_SECRET || 'your-secret-key'));

// Enhanced session store with better error handling
const sessionStore = new MySQLStore({
    host: config.db.host,
    port: config.db.port,
    user: config.db.user,
    password: config.db.password,
    database: config.db.database,
    createDatabaseTable: true,
    schema: {
        tableName: 'user_sessions',
        columnNames: {
            session_id: 'session_id',
            expires: 'expires',
            data: 'data'
        }
    },
    clearExpired: true,
    checkExpirationInterval: 900000, // 15 minutes
    expiration: config.session.maxAge,
    connectionLimit: 10,
    retries: 5,
    retryStrategy: (times) => Math.min(times * 100, 5000),
    onError: async (err) => {
        logger.error(`Session store error: ${err.message}`);
        if (err.code === 'PROTOCOL_CONNECTION_LOST') {
            logger.warn('Attempting to reconnect to session store...');
            try {
                await sessionStore.connection.reconnect();
                logger.info('Session store reconnected successfully');
            } catch (reconnectErr) {
                logger.error(`Session store reconnection failed: ${reconnectErr.message}`);
            }
        }
    }
});

// Session configuration with enhanced security
app.use(session({
    store: sessionStore,
    name: config.session.name,
    secret: config.session.secret,
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: {
        httpOnly: true,
        secure: config.session.secure,
        maxAge: config.session.maxAge,
        sameSite: 'lax',
        domain: config.session.cookieDomain,
        path: '/'
    },
    genid: () => {
        const sessionId = uuidv4();
        logger.debug(`Generated new session ID: ${sessionId}`);
        return sessionId;
    }
}));

// Session store event listeners
sessionStore.on('connect', () => logger.info('Session store connected'));
sessionStore.on('disconnect', () => logger.warn('Session store disconnected'));
sessionStore.on('sessionError', (err) => logger.error(`Session error: ${err.message}`));

// CSRF protection
app.use(csrf({ cookie: true }));
app.use((req, res, next) => {
    res.locals.csrfToken = req.csrfToken();
    next();
});

app.use(flash());

// Enhanced Passport configuration with debugging
passport.use(new LocalStrategy(
    {
        usernameField: 'username',
        passwordField: 'password',
        passReqToCallback: true
    },
    async (req, username, password, done) => {
        try {
            logger.debug(`Login attempt for username: ${username}`);
            
            const [users] = await req.db.query(
                'SELECT * FROM Users WHERE LOWER(Username) = LOWER(?)', 
                [username]
            );
            
            if (users.length === 0) {
                logger.warn(`User not found: ${username}`);
                return done(null, false, { 
                    message: 'Incorrect username or password.' 
                });
            }

            const user = users[0];
            logger.debug(`User found: ${user.Username} (ID: ${user.Id})`);
            
            const isValid = await bcrypt.compare(password, user.Password);
            if (!isValid) {
                logger.warn(`Invalid password for user: ${username}`);
                return done(null, false, { 
                    message: 'Incorrect username or password.' 
                });
            }

            logger.info(`Successful login for user: ${username}`);
            return done(null, user);
        } catch (err) {
            logger.error(`Login error: ${err.stack}`);
            return done(err);
        }
    }
));

// Serialization with enhanced logging
passport.serializeUser((user, done) => {
    logger.debug(`Serializing user ID: ${user.Id}`);
    done(null, user.Id);
});

passport.deserializeUser(async (id, done) => {
    try {
        logger.debug(`Deserializing user ID: ${id}`);
        const [users] = await dbPool.query(
            'SELECT Id, Username, Email, Role FROM Users WHERE Id = ?',
            [id]
        );
        
        if (users.length === 0) {
            logger.warn(`User not found during deserialization: ${id}`);
            return done(new Error('User not found'));
        }
        
        const user = users[0];
        logger.debug(`Deserialized user: ${user.Username}`);
        done(null, user);
    } catch (err) {
        logger.error(`Deserialization error: ${err.stack}`);
        done(err);
    }
});

app.use(passport.initialize());
app.use(passport.session());

// Enhanced request logging
app.use(morgan(process.env.NODE_ENV === 'development' ? 'dev' : 'combined', { 
    stream: { 
        write: (message) => logger.info(message.trim()) 
    } 
}));

// Flash messages and user context
app.use((req, res, next) => {
    res.locals.user = req.user || null;
    res.locals.isAuthenticated = req.isAuthenticated();
    
    res.locals.messages = {
        success: req.flash('success'),
        error: req.flash('error'),
        info: req.flash('info'),
        warning: req.flash('warning')
    };
    
    res.locals.requestId = req.id;
    next();
});

// CORS with credentials support
app.use(cors({
    origin: (origin, callback) => {
        if (!origin || config.security.corsOrigins.includes(origin | ['http://localhost:3000'])) {
            callback(null, true);
        } else {
            logger.warn(`CORS blocked for origin: ${origin}`);
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token'],
    exposedHeaders: ['X-Request-ID']
}));

// Body parsers with size limits
app.use(express.urlencoded({ 
    extended: true, 
    limit: '10kb',
    parameterLimit: 100
}));
app.use(express.json({ 
    limit: '10kb',
    strict: true
}));

// View engine setup with multiple directories
app.set('view engine', 'ejs');
app.set('views', [
    path.join(__dirname, 'views/User'),
    path.join(__dirname, 'views/Admin'),
    path.join(__dirname, 'views/Shared')
]);

// Static files with cache control
app.use('/Public', express.static(path.join(__dirname, 'Public'), {
    maxAge: process.env.NODE_ENV === 'production' ? '1y' : 0,
    setHeaders: (res, path) => {
        if (path.endsWith('.css')) {
            res.setHeader('Content-Type', 'text/css');
        }
        if (path.endsWith('.html')) {
            res.setHeader('Cache-Control', 'no-store');
        }
    }
}));

// Security headers for auth routes
app.use('/auth', (req, res, next) => {
    res.set({
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'Referrer-Policy': 'no-referrer'
    });
    next();
});

// Rate limiting for auth routes
app.use('/auth/login', authLimiter);

// Health check endpoint with DB verification
app.get('/health', async (req, res) => {
    try {
        await req.db.query('SELECT 1');
        res.status(200).json({
            status: 'ok',
            database: 'connected',
            timestamp: new Date().toISOString(),
            uptime: process.uptime(),
            memoryUsage: process.memoryUsage()
        });
    } catch (err) {
        logger.error(`Health check failed: ${err.message}`);
        res.status(503).json({
            status: 'unhealthy',
            database: 'disconnected',
            error: err.message
        });
    }
});

// Debug routes for development (protected)
if (process.env.NODE_ENV !== 'production') {
    app.get('/debug/session', ensureAuthenticated, (req, res) => {
        res.json({
            sessionId: req.sessionID,
            authenticated: req.isAuthenticated(),
            user: req.user,
            session: req.session
        });
    });
    
    app.get('/debug/test-auth', ensureAuthenticated, (req, res) => {
        if (req.isAuthenticated()) {
            return res.json({
                status: 'authenticated',
                user: req.user
            });
        }
        res.json({
            status: 'not authenticated',
            session: req.session
        });
    });
    
    app.get('/debug/test-password/:password', ensureAuthenticated, async (req, res) => {
        try {
            const [users] = await req.db.query('SELECT Username, Password FROM Users LIMIT 1');
            if (users.length === 0) {
                return res.json({ error: 'No users in database' });
            }
            
            const user = users[0];
            const match = await bcrypt.compare(req.params.password, user.Password);
            
            res.json({
                username: user.Username,
                passwordMatch: match,
                storedHash: user.Password
            });
        }
        catch (err) {
            res.status(500).json({ error: err.message });
        }
    });
}

// Routes
app.use('/', require('./router/AuthRoutes/router'));

// Authentication middleware
function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    
    logger.warn(`Unauthenticated access attempt to: ${req.originalUrl}`);
    req.session.returnTo = req.originalUrl;
    req.flash('error', 'Please login to access this page');
    res.redirect('/auth/login');
}

function ensureAdmin(req, res, next) {
    if (req.isAuthenticated() && req.user.Role === 'admin') {
        return next();
    }
    
    logger.warn(`Unauthorized admin access attempt by: ${req.user?.Username || 'anonymous'}`);
    res.status(403).render('error', {
        message: 'Forbidden',
        statusCode: 403,
        user: req.user
    });
}

// Error handlers
app.use((req, res) => {
    logger.warn(`404 Not Found: ${req.method} ${req.originalUrl}`);
    res.status(404).render('error', {
        message: 'Page not found',
        statusCode: 404,
        user: req.user
    });
});

app.use((err, req, res, next) => {
    logger.error(`Error [${req.id}]: ${err.stack}`);
    
    if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
        return res.status(400).json({ error: 'Invalid JSON' });
    }
    
    if (err.code === 'EBADCSRFTOKEN') {
        return res.status(403).render('error', {
            message: 'Invalid CSRF token',
            statusCode: 403,
            user: req.user
        });
    }
    
    res.status(err.status || 500).render('error', {
        message: err.message || 'Something went wrong',
        statusCode: err.status || 500,
        user: req.user,
        stack: process.env.NODE_ENV !== 'production' ? err.stack : undefined
    });
});

// Server startup with enhanced verification
async function startServer() {
    try {
        // Initialize database pool
        dbPool = await db.pool;
        const conn = await dbPool.getConnection();
        conn.release();
        logger.info('Database pool initialized successfully');
        
        // Verify database query API
        try {
            const [testResult] = await dbPool.query('SELECT 1 AS test');
            if (!Array.isArray(testResult) || testResult[0].test !== 1) {
                throw new Error('Unexpected database query result format');
            }
        } catch (err) {
            throw new Error(`Database query API validation failed: ${err.message}`);
        }
        
        
};





// Start the server
startServer();

