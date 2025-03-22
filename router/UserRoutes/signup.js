const express = require('express');
const { body, validationResult } = require('express-validator');
const router = express.Router();
const userController = require('../../controllers/UserController/signupController');

const validateUser = [
  body('username').notEmpty().withMessage('Username is required'),
  body('email').isEmail().withMessage('Invalid email address'),
  body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    next();
  },
];

router.post('/submit', validateUser, userController.submitUser);

module.exports = router;