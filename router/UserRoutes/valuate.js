const express = require('express');
const router = express.Router();
const valuationController = require('../../controllers/UserController/valuateController');

router.get('/valuate', valuationController.getValuationPage);
router.post('/valuate', valuationController.postValuation);

module.exports = router;