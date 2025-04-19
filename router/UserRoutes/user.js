const express = require('express');
const router = express.Router();
const isAuthenticated = require('../../Middleware/authmiddleware');
const userProfileController = require('../../controllers/UserController/userprofileController');

router.get('/User/profile', isAuthenticated, userProfileController.getUserProfile);
router.post('/User/profile', isAuthenticated, userProfileController.updateUserProfile);

module.exports = router;