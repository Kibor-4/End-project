const express = require('express');
const router = express.Router();
const authController = require('../../controllers/AuthController/authcontroller'); // Assuming authController is in authController.js

// Routes
router.get('/login', (req, res) => {
    res.render('login', { error: null, redirect: req.query.redirect });
 
});

router.post('/login', authController.login);
router.get('/signup', authController.signup);
router.post('/register', authController.register);
router.get('/logout', authController.logout);

module.exports = router;