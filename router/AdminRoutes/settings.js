const express = require('express');
const settingsController = require('../../controllers/AdminController/settingsController');

const router = express.Router();

// Route to render the settings page
router.get('/admin/settings', settingsController.getSettings);

// Route to handle creating a new admin
router.post('/admin/create-admin', settingsController.createAdmin);

module.exports = router;