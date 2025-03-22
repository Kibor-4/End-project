const express = require('express');
const router = express.Router();
const analyticsController = require('../../controllers/AdminController/analyticsController');

// Route for the Analytics page
router.get('/admin/analytics', analyticsController.getAnalytics);

module.exports = router;