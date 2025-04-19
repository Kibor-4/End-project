const express = require('express');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const path = require('path');
const cors = require('cors');
const db = require('./database/db'); // Import the database instance
const helmet = require('helmet');
const { v4: uuidv4 } = require('uuid');
const rateLimit = require('express-rate-limit');
const winston = require('winston');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const morgan = require('morgan');
const { validationResult } = require('express-validator');
// const csrf = require('csurf'); // Removed csurf import
require('dotenv').config();

// Configuration validation
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
    cookieDomain: process.env.COOKIE_DOMAIN,
    secure: process.env.NODE_ENV === 'production'
  },
  security: {
    corsOrigins: process.env.ALLOWED_ORIGINS?.split(',') || [],
    rateLimit: {
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 100
    }
  },
  admin: {
    email: process.env.DEFAULT_ADMIN_EMAIL || 'admin@example.com',
    password: process.env.DEFAULT_ADMIN_PASSWORD
  }
};

// Validate required configuration
['DB_HOST', 'DB_USER', 'DB_PASSWORD', 'DB_NAME', 'SESSION_SECRET'].forEach(envVar => {
  if (!process.env[envVar]) {
    throw new Error(`Missing required environment variable: ${envVar}`);
  }
});

// Logger setup
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' })
  ]
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}

const app = express();

// Database connection middleware
let dbPool;
(async () => {
  try {
    dbPool = await db.pool; // Access the pool from the exported instance
    await dbPool.getConnection().then(conn => conn.release()); // Test connection
    logger.info('Database pool initialized');
  } catch (err) {
    logger.error(`Failed to initialize database pool: ${err.message}`);
    process.exit(1);
  }
})();

app.use(async (req, res, next) => {
  if (dbPool) {
    req.db = dbPool;
    next();
  } else {
    logger.error('Database pool not initialized');
    res.status(503).render('error', { message: 'Service unavailable', statusCode: 503, user: null });
  }
});

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:']
    }
  },
  hsts: {
    maxAge: 63072000,
    includeSubDomains: true,
    preload: true
  }
}));
app.disable('x-powered-by');

// Rate limiting
const apiLimiter = rateLimit({
  windowMs: config.security.rateLimit.windowMs,
  max: config.security.rateLimit.max,
  message: 'Too many requests, please try again later.'
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20,
  message: 'Too many login attempts, please try again later.'
});

app.use(cookieParser());
// app.use(csrf({ cookie: true })); // Removed csurf middleware

// Session configuration
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
  expiration: 86400000, // 1 day
  connectionLimit: 10,
  retries: 3,
  onError: err => logger.error(`Session store error: ${err.message}`)
});

app.use(session({
  store: sessionStore,
  name: 'sessionId',
  secret: config.session.secret,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    httpOnly: true,
    secure: config.session.secure,
    maxAge: 86400000, // 1 day
    sameSite: 'lax',
    domain: config.session.cookieDomain
  },
  genid: uuidv4
}));

// Passport configuration
passport.use(new LocalStrategy(
  { usernameField: 'email', passwordField: 'password' },
  async (email, password, done) => {
    try {
      const [users] = await dbPool.query('SELECT * FROM Users WHERE email = ?', [email]);
      if (users.length === 0) {
        return done(null, false, { message: 'Incorrect email or password.' });
      }

      const isValid = await bcrypt.compare(password, users[0].password);
      if (!isValid) {
        return done(null, false, { message: 'Incorrect email or password.' });
      }

      return done(null, users[0]);
    } catch (err) {
      return done(err);
    }
  }
));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const [users] = await dbPool.query(
      'SELECT id, email, Username, role FROM Users WHERE id = ?',
      [id]
    );
    done(null, users[0]);
  } catch (err) {
    done(err);
  }
});

app.use(passport.initialize());
app.use(passport.session());

// Request logging
app.use(morgan('combined', { stream: { write: message => logger.info(message.trim()) } }));

app.use((req, res, next) => {
  req.requestId = uuidv4();
  logger.info('Request', {
    requestId: req.requestId,
    method: req.method,
    url: req.originalUrl,
    ip: req.ip,
    sessionId: req.sessionID || 'none',
    userAgent: req.get('User-Agent')
  });

  res.locals.user = req.user || null;
  res.locals.isAuthenticated = req.isAuthenticated();
  // res.locals.csrfToken = req.csrfToken(); // Removed csrfToken from res.locals
  next();
});

// CORS configuration
app.use(cors({
  origin: config.security.corsOrigins.length > 0
    ? config.security.corsOrigins
    : true,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
}));

// Body parsers
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(express.json({ limit: '10kb' }));

// View engine setup
app.set('view engine', 'ejs');
app.set('views', [
  path.join(__dirname, 'views/User'),
  path.join(__dirname, 'views/Admin'),
  path.join(__dirname, 'views/Shared')
]);

// Static files
app.use('/Public', express.static(path.join(__dirname, 'Public'), {
  maxAge: process.env.NODE_ENV === 'production' ? '1y' : 0,
  setHeaders: (res, path) => {
    if (path.endsWith('.css')) {
      res.setHeader('Content-Type', 'text/css');
    }
  }
}));

// Cache control for sensitive routes
app.use('/login', (req, res, next) => {
  res.set('Cache-Control', 'no-store');
  next();
});

// Health check endpoint
app.get('/health', async (req, res) => {
  try {
    await req.db.query('SELECT 1'); // Use req.db
    res.status(200).json({
      status: 'ok',
      database: 'connected',
      timestamp: new Date().toISOString(),
      uptime: process.uptime()
    });
  } catch (err) {
    res.status(503).json({
      status: 'unhealthy',
      database: 'disconnected',
      error: err.message
    });
  }
});

// Session debug route (development only)
if (process.env.NODE_ENV !== 'production') {
  app.get('/session-info', (req, res) => {
    res.json({
      sessionId: req.sessionID,
      authenticated: req.isAuthenticated(),
      user: req.user
    });
  });
}

app.get('/about', (req, res) => {
  res.render('about'); 
});
// Mount the main router
app.use('/', require('./router/AuthRoutes/router'));

// Authentication middleware (defined after router to be used in routes)
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  req.session.returnTo = req.originalUrl;
  res.redirect('/login');
}

function ensureAdmin(req, res, next) {
  if (req.isAuthenticated() && req.user.role === 'admin') {
    return next();
  }
  res.status(403).render('error', {
    message: 'Forbidden',
    statusCode: 403,
    user: res.locals.user
  });
}

// Error handlers
app.use((req, res) => {
  logger.warn(`404: ${req.method} ${req.originalUrl}`);
  res.status(404).render('error', {
    message: 'Page not found',
    statusCode: 404,
    user: res.locals.user
  });
});

app.use((err, req, res, next) => {
  logger.error(`Error [${req.requestId}]: ${err.stack}`);

  // Removed CSRF token error handling block

  res.status(err.status || 500).render('error', {
    message: err.message || 'Something went wrong',
    statusCode: err.status || 500,
    user: res.locals.user,
    requestId: process.env.NODE_ENV !== 'production' ? req.requestId : undefined
  });
});

// Server startup
async function startServer() {
  try {
    await verifySchema(db.pool); // Use db.pool
    await createDefaultAdmin(db.pool); // Use db.pool

    const port = process.env.PORT || 8100;
    app.listen(port, () => {
      logger.info(`Server started on port ${port}`);
      logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);

      if (process.env.NODE_ENV !== 'production') {
        logger.warn('Running in development mode - security features may be relaxed');
      }
    });
  } catch (err) {
    logger.error(`Server startup failed: ${err.message}`);
    process.exit(1);
  }
}

async function verifySchema(pool) {
  const requiredTables = ['Users', 'user_sessions', 'Properties'];
  const missingTables = [];

  for (const table of requiredTables) {
    const [result] = await pool.query('SHOW TABLES LIKE ?', [table]);
    if (result.length === 0) {
      missingTables.push(table);
    }
  }

  if (missingTables.length > 0) {
    throw new Error(`Missing required tables: ${missingTables.join(', ')}`);
  }
}

async function createDefaultAdmin(pool) {
  try {
    const [admins] = await pool.query(
      'SELECT * FROM Users WHERE role = ? AND email = ?',
      ['admin', config.admin.email]
    );

    if (admins.length === 0 && config.admin.password) {
      const hashedPassword = await bcrypt.hash(config.admin.password, 10);
      await pool.query(
        'INSERT INTO Users (email, password, Username, role) VALUES (?, ?, ?, ?)',
        [config.admin.email, hashedPassword, 'Admin', 'admin']
      );
      logger.info('Default admin account created');
    }
  } catch (err) {
    logger.warn(`Failed to create default admin: ${err.message}`);
  }
}

startServer();