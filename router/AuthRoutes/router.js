const express = require('express');
const router = express.Router();
const passport = require('./passportconfig');
const authRoutes = require('./auth');
const profile = require('../UserRoutes/user');
const propertydetails = require('../UserRoutes/property');
const userdashboard = require('../UserRoutes/dash');
const addPropertyRouter = require('../UserRoutes/addproperty');
const saleRouter = require('../UserRoutes/salerouter');
const adminRoutes = require('../AdminRoutes/dashboard');
const propertyRoutes = require('../AdminRoutes/properties');
const analyticsRoutes = require('../AdminRoutes/analytics');
const settingsRoutes = require('../AdminRoutes/Adminsettings');
const transactionRoutes = require('../AdminRoutes/transaction');
const Users = require('../AdminRoutes/user_management');
const logger = require('./logger');
const chats = require('../UserRoutes/chat');
const signupRouter = require('../../router/UserRoutes/signup'); // Fixed import

// Public routes
router.use('/', authRoutes);
router.use('/', signupRouter); // Fixed usage - mounted under /auth

// Public home, about, and valuate routes
router.get('/', (req, res) => {
    res.render('index');
});

router.get('/about', (req, res) => {
    res.render('about');
});

router.get('/valuate', (req, res) => {
    res.render('valuate');
});

// Authentication middleware
const isAuthenticated = (req, res, next) => {
    if (req.isAuthenticated()) {
        return next();
    }
    logger.warn(`Unauthorized access attempt to ${req.originalUrl}`);
    res.status(401).render('error', {
        message: 'Please login to access this page',
        statusCode: 401,
        user: null
    });
};

// User routes (require authentication)
const userRouter = express.Router();
userRouter.use(isAuthenticated);
userRouter.use('/', profile);
userRouter.use('/', propertydetails);
userRouter.use('/', userdashboard);
userRouter.use('/', addPropertyRouter);
userRouter.use('/', saleRouter);
router.use('/user', userRouter);

// Admin authentication middleware
const isAdmin = (req, res, next) => {
    if (req.isAuthenticated() && req.user.role === 'admin') {
        return next();
    }
    logger.warn(`Unauthorized admin access attempt by user ${req.user?.id || 'anonymous'}`);
    res.status(403).render('error', {
        message: 'Access denied',
        statusCode: 403,
        user: req.user || null
    });
};

// Protected admin routes
const adminRouter = express.Router();
adminRouter.use(isAuthenticated, isAdmin);
adminRouter.use('/', adminRoutes);
adminRouter.use('/', propertyRoutes);
adminRouter.use('/', analyticsRoutes);
adminRouter.use('/', settingsRoutes);
adminRouter.use('/', transactionRoutes);
adminRouter.use('/', Users);
router.use('/admin', adminRouter);

// Enhanced logout
router.get('/logout', (req, res, next) => {
    if (!req.isAuthenticated()) {
        return res.redirect('/login');
    }

    const userId = req.user.id;
    const requestId = req.requestId;

    req.logout((err) => {
        if (err) {
            logger.error(`Logout error for user ${userId}: ${err.message}`);
            return next(err);
        }
        logger.info(`User ${userId} logged out successfully`);
        res.redirect('/login');
    });
});

module.exports = router;