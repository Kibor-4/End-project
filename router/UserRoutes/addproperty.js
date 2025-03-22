const express = require('express');
const router = express.Router();
const { submitProperty } = require('../../controllers/UserController/addpropertyController');
const isAuthenticated = require('../../Middleware/authmiddleware');
const upload = require('../../Public/Uploads/multer');

router.get('/addproperty', isAuthenticated, (req, res) => {
    res.render('addproperty');
});

router.post('/submit', isAuthenticated, upload.array('images'), submitProperty);

module.exports = router;
