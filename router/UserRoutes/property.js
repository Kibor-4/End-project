
const express = require('express');
const router = express.Router();
const propertyController = require('../../controllers/UserController/propertyController');
const isAuthenticated = require('../../Middleware/authmiddleware');

router.get('/User/property/:id', propertyController.getPropertyDetails);
router.post('/User/properties/:id/reviews', isAuthenticated, propertyController.addPropertyReview);

module.exports = router;