const express = require('express');
const router = express.Router();
const authController = require('../../controllers/AuthController/authcontroller');

// Routes
router.get('/login', (req, res) => {
    res.render('login', { error: null, redirect: req.query.redirect });
});

// Add proper handlers for POST routes
router.post('/login', authController.login);  // Assuming you have login method in authController


// GET routes
router.get('/signup', (req, res) => {
    res.render('signup', { error: null });
});

router.get('/logout', authController.logout);  // Assuming you have logout method in authController

module.exports = router;