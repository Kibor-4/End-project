const express = require('express');
const propertyController = require('../../controllers/AdminController/propertyController');

const router = express.Router();

// Route to render the properties page
router.get('/admin/properties', propertyController.getProperties);

module.exports = router;