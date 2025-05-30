const express = require('express');
const router = express.Router();
const dashboardController = require('../../controllers/UserController/dashController');

// Dashboard route
router.get('/User/dashboard', dashboardController.getDashboard);

module.exports = router;