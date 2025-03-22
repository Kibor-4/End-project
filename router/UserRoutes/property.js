
const express = require('express');
const router = express.Router();
const propertyController = require('../../controllers/UserController/propertyController');
const isAuthenticated = require('../../Middleware/authmiddleware');

router.get('/property/:id', propertyController.getPropertyDetails);
router.post('/properties/:id/reviews', isAuthenticated, propertyController.addPropertyReview);

module.exports = router;