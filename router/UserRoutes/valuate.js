const express = require('express');
const router = express.Router();
const valuationController = require('../../controllers/UserController/valuateController');

router.get('/User/valuate', valuationController.getValuationPage);
router.post('/User/valuate', valuationController.postValuation);

module.exports = router;