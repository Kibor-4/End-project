const express = require('express');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const path = require('path');
const cors = require('cors');
const getPool = require('./database/db');
const fs = require('fs');
const helmet = require('helmet');
const { v4: uuidv4 } = require('uuid');
const rateLimit = require('express-rate-limit');
const winston = require('winston');
require('dotenv').config();
require('crypto').randomBytes(64).toString('hex');

// Configure logger
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

// Route imports
const userRoutes = require('./router/UserRoutes/signup');
const authRoutes = require('./router/AuthRoutes/auth');
const addPropertyRouter = require('./router/UserRoutes/addproperty');
const saleRouter = require('./router/UserRoutes/salerouter');
const profile = require('./router/UserRoutes/user');
const propertydetails = require('./router/UserRoutes/property');
const userdashboard = require('./router/UserRoutes/dash');
const home = require('./router/UserRoutes/index');
const adminRoutes = require('./router/AdminRoutes/dashboard');
const propertyRoutes = require('./router/AdminRoutes/properties');
const analyticsRoutes = require('./router/AdminRoutes/analytics');
const settingsRoutes = require('./router/AdminRoutes/settings');
const transactionRoutes = require('./router/AdminRoutes/transaction');
const Users = require('./router/AdminRoutes/user_management');

const app = express();

// Validate environment variables
const requiredEnvVars = ['DB_HOST', 'DB_USER', 'DB_PASSWORD', 'DB_NAME', 'SESSION_SECRET'];
for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    logger.error(`Missing required environment variable: ${envVar}`);
    process.exit(1);
  }
}

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later'
});
app.use(limiter);

// Database connection check middleware
app.use(async (req, res, next) => {
  try {
    const pool = await getPool;
    await pool.query('SELECT 1');
    next();
  } catch (err) {
    logger.error(`Database connection error: ${err.message}`);
    return res.status(503).render('error', {
      message: 'Service temporarily unavailable',
      statusCode: 503,
      user: null
    });
  }
});

// Session configuration
const sessionStore = new MySQLStore({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT || 3306,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  createDatabaseTable: true,
  schema: {
    tableName: 'user_sessions',
    columnNames: {
      session_id: 'session_id',
      expires: 'expires',
      data: 'data',
      //user_id: 'user_id' // Ensure this matches your table structure
    }
  },
  clearExpired: true,
  checkExpirationInterval: 900000, // 15 minutes
  expiration: 86400000, // 24 hours
  connectionLimit: 10,
  retries: 3,
  onError: (err) => logger.error(`Session store error: ${err.message}`)
});

const sessionSecret = process.env.SESSION_SECRET;
if (!sessionSecret && process.env.NODE_ENV === 'production') {
  logger.error('FATAL: SESSION_SECRET must be configured in production');
  process.exit(1);
}

app.use(session({
  store: sessionStore,
  name: 'sessionId',
  secret: sessionSecret || require('crypto').randomBytes(64).toString('hex'),
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    maxAge: 86400000, // 24 hours
    sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax',
    domain: process.env.COOKIE_DOMAIN || undefined
  },
  genid: () => uuidv4()
}));

// Enhanced logging middleware with request ID
app.use((req, res, next) => {
  req.requestId = uuidv4();
  const logData = {
    requestId: req.requestId,
    timestamp: new Date().toISOString(),
    method: req.method,
    url: req.originalUrl,
    ip: req.ip,
    sessionId: req.sessionID || 'none',
    userAgent: req.get('User-Agent')
  };

  logger.info('Incoming request', logData);
  next();
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
    maxAge: 63072000, // 2 years
    includeSubDomains: true,
    preload: true
  }
}));
app.disable('x-powered-by');

app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || true,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
}));

// Body parsing with size limits
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(express.json({ limit: '10kb' }));

// View engine setup
app.set('view engine', 'ejs');
app.set('views', [
  path.join(__dirname, 'views/User'),
  path.join(__dirname, 'views/Admin'),
  path.join(__dirname, 'views/Shared'),
]);

// Static files with cache control
app.use('/Public', express.static(path.join(__dirname, 'Public'), {
  maxAge: process.env.NODE_ENV === 'production' ? '1y' : 0,
  setHeaders: (res, path) => {
    if (path.endsWith('.css')) {
      res.setHeader('Content-Type', 'text/css');
    }
  }
}));

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// Combined Home Routes
app.get('/', (req, res) => {
  if (req.session.user) {
    return res.redirect(req.session.user.role === 'admin' ? '/admin' : '/user_dashboard');
  }
  res.render('index', { user: null });
});

// Public routes
app.use('/', authRoutes);
app.use('/', userRoutes);

// User routes (require authentication)
const userRouter = express.Router();
userRouter.use((req, res, next) => {
  if (!req.session.user) {
    logger.warn(`Unauthorized access attempt to ${req.originalUrl}`);
    return res.status(401).render('error', {
      message: 'Please login to access this page',
      statusCode: 401,
      user: null
    });
  }
  next();
});
userRouter.use('/', profile);
userRouter.use('/', propertydetails);
userRouter.use('/', userdashboard);
userRouter.use('/', addPropertyRouter);
userRouter.use('/', saleRouter);
app.use('/', userRouter);

// Admin authentication middleware
const isAdmin = (req, res, next) => {
  if (req.session.user?.role === 'admin') {
    return next();
  }
  logger.warn(`Unauthorized admin access attempt by user ${req.session.user?.id || 'anonymous'}`);
  res.status(403).render('error', {
    message: 'Access denied',
    statusCode: 403,
    user: req.session.user || null
  });
};

// Protected admin routes
const adminRouter = express.Router();
adminRouter.use(isAdmin);
adminRouter.use('/', adminRoutes);
adminRouter.use('/', propertyRoutes);
adminRouter.use('/', analyticsRoutes);
adminRouter.use('/', settingsRoutes);
adminRouter.use('/', transactionRoutes);
adminRouter.use('/', Users);
app.use('/admin', adminRouter);

// Basic routes
app.get('/about', (req, res) => {
  res.render('about', {
    user: req.session.user || null,
    currentUrl: req.originalUrl
  });
});

// Enhanced logout
app.get('/logout', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }

  const userId = req.session.user.id;
  const requestId = req.requestId;

  req.session.destroy((err) => {
    if (err) {
      logger.error(`Logout error for user ${userId}: ${err.message}`);
      return res.status(500).render('error', {
        message: 'Logout failed',
        statusCode: 500,
        user: null
      });
    }

    res.clearCookie('sessionId');
    logger.info(`User ${userId} logged out successfully`);
    res.redirect('/login');
  });
});

// 404 handler
app.use((req, res) => {
  logger.warn(`404 Not Found: ${req.method} ${req.originalUrl}`);
  res.status(404).render('error', {
    message: 'Page not found',
    statusCode: 404,
    user: req.session.user || null
  });
});

// Error handling
app.use((err, req, res, next) => {
  const requestId = req.requestId || 'none';
  logger.error(`Error [${req.method} ${req.url}]: ${err.stack}`);

  const statusCode = err.statusCode || 500;
  res.status(statusCode).render('error', {
    message: err.message || 'Something went wrong',
    statusCode,
    user: req.session.user || null,
    requestId: process.env.NODE_ENV !== 'production' ? requestId : undefined
  });
});

// Server startup
async function startServer() {
  try {
    const pool = await getPool;
    
    // Verify database structure
    try {
      await verifySchema(pool);
      logger.info('Database schema verification successful');
    } catch (err) {
      logger.warn(`Database schema verification warning: ${err.message}`);
    }

    const port = process.env.PORT || 8100;
    app.listen(port, () => {
      logger.info(`Server running on port ${port}`);
      logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
    });
  } catch (err) {
    logger.error(`Server startup failed: ${err.message}`);
    process.exit(1);
  }
}

async function verifySchema(pool) {
  const requiredTables = ['Users', 'user_sessions', 'Properties'];
  for (const table of requiredTables) {
    const [result] = await pool.query('SHOW TABLES LIKE ?', [table]);
    if (result.length === 0) {
      throw new Error(`Missing required table: ${table}`);
    }
  }
  
  // Verify critical columns
  await pool.query('SELECT id, username, password, role FROM Users LIMIT 1');
  await pool.query('SELECT session_id, expires, data, user_id FROM user_sessions LIMIT 1');
}

startServer();