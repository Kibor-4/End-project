const express = require('express');
const router = express.Router();
const authRoutes = require('./auth');
const userRoutes = require('../UserRoutes/signup');
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
const logger = require('./logger'); // Assuming you have a logger.js file

// Combined Home Routes
router.get('/', (req, res) => {
  if (req.session.user) {
    return res.redirect(req.session.user.role === 'admin' ? '/admin' : '/user_dashboard');
  }
  res.render('index', { user: null });
});

// Public routes
router.use('/', authRoutes);
router.use('/', userRoutes);

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
router.use('/', userRouter);

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
router.use('/', adminRouter);

// Basic routes
router.get('/about', (req, res) => {
  res.render('about', {
    user: req.session.user || null,
    currentUrl: req.originalUrl
  });
});

// Enhanced logout
router.get('/logout', (req, res) => {
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

module.exports = router;