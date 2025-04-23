const express = require('express');
const router = express.Router();
const signupController = require('../../controllers/AuthController/signupController');

// Route to display the signup form
router.get('/signup', signupController.renderSignupPage);

// Route to handle form submission
router.post('/signup', signupController.submitUser);

module.exports = router;