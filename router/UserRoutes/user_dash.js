const express = require('express');
const router = express.Router();
const isAuthenticated = require('../AuthRoutes/authmiddleware');
const adminDashboardController = require('../controllers/adminDashboardController');

router.get('/dashboard', isAuthenticated, adminDashboardController.getAdminDashboard);

module.exports = router;