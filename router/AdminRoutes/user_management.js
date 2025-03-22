const express = require('express');
const userController = require('../../controllers/AdminController/user_managementController');

const router = express.Router();

// Route to render the user management page
router.get('/admin/users', userController.getUsers);

// Route to handle user deletion
router.post('/admin/users/delete/:id', userController.deleteUser);

// Route to handle user editing
router.post('/admin/users/edit/:id', userController.editUser);

module.exports = router;