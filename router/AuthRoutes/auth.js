const express = require('express');
const router = express.Router();
const authController = require('../../controllers/AuthController/authcontroller');

// Login routes
router.get('/login', authController.getLogin);
router.post('/login', authController.postLogin);

// Registration routes
router.get('/register', authController.getRegister);
router.post('/register', authController.postRegister);

// Logout route
router.get('/logout', authController.getLogout);

// Password reset routes
router.get('/forgot-password', authController.getForgotPassword);
router.post('/forgot-password', authController.postForgotPassword);
router.get('/reset-password/:token', authController.getResetPassword);
router.post('/reset-password/:token', authController.postResetPassword);

module.exports = router;