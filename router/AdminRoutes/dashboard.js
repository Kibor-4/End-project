const express = require('express');
const dashboardController = require('../../controllers/AdminController/dashboardController');

const router = express.Router();

// Route to render the dashboard page
router.get('/admin', dashboardController.getDashboard);

module.exports = router;