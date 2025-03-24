// server.js - Corrected Version

const express = require('express');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const path = require('path');
const cors = require('cors');
const getPool = require('./database/db');
const fs = require('fs');
const helmet = require('helmet');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

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

// Database connection check middleware (moved to the top)
app.use(async (req, res, next) => {
    try {
        const pool = await getPool;
        await pool.query('SELECT 1');
        next();
    } catch (err) {
        console.error(`[${req.requestId}] Database connection error:`, err);
        return res.status(503).render('error', {
            message: 'Service temporarily unavailable',
            statusCode: 503,
            user: null
        });
    }
});

// Session configuration should come before routes that use sessions
const sessionStore = new MySQLStore({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT || 3306,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    createDatabaseTable: false,
    schema: {
        tableName: 'user_sessions',
        columnNames: {
            session_id: 'session_id',
            expires: 'expires',
            data: 'data',
        }
    },
    clearExpired: true,
    checkExpirationInterval: 900000, // 15 minutes
    expiration: 86400000 // 24 hours
});

app.use(session({
    store: sessionStore,
    name: 'sessionId',
    secret: process.env.SESSION_SECRET || require('crypto').randomBytes(64).toString('hex'),
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
    const now = new Date().toISOString();
    const logData = {
        requestId: req.requestId,
        timestamp: now,
        method: req.method,
        url: req.originalUrl,
        ip: req.ip,
        sessionId: req.sessionID || 'none',
        userAgent: req.get('User-Agent')
    };

    const logMessage = `${JSON.stringify(logData)}\n`;

    fs.appendFile('server.log', logMessage, (err) => {
        if (err) console.error('Logging error:', err);
    });

    console.log(`[<span class="math-inline">\{now\}\] \[</span>{req.requestId}] ${req.method} ${req.originalUrl}`);
    next();
});

// Security middleware
app.use(helmet());
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
            console.error(`[${requestId}] Logout error for user ${userId}:`, err);
            return res.status(500).render('error', {
                message: 'Logout failed',
                statusCode: 500,
                user: null
            });
        }

        res.clearCookie('sessionId');
        console.log(`[${requestId}] User ${userId} logged out successfully`);
        res.redirect('/login');
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).render('error', {
        message: 'Page not found',
        statusCode: 404,
        user: req.session.user || null
    });
});

// Error handling
app.use((err, req, res, next) => {
    const requestId = req.requestId || 'none';
    console.error(`[${requestId}] Error [${req.method} ${req.url}]:`, err.stack);

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
            const [usersTable] = await pool.query('SHOW TABLES LIKE "Users"');
            const [sessionsTable] = await pool.query('SHOW TABLES LIKE "user_sessions"');

            if (usersTable.length > 0 && sessionsTable.length > 0) {
                await pool.query('SELECT last_login FROM Users LIMIT 1');
                await pool.query('SELECT user_id FROM user_sessions LIMIT 1');
            } else {
                console.warn('Database schema warning: Users or user_sessions table does not exist.');
            }
        } catch (err) {
            if (err.code === 'ER_BAD_FIELD_ERROR') {
                console.warn('Database schema warning:', err.message);
            }
        }

        const port = process.env.PORT || 8100;
        app.listen(port, () => {
            console.log(`Server running on port ${port}`);
            console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
            console.log(`Session secret: ${process.env.SESSION_SECRET ? 'set' : 'using temporary key'}`);
        });
    } catch (err) {
        console.error("Server startup failed:", err);
        process.exit(1);
    }
}

startServer();