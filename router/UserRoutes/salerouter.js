const express = require('express');
const router = express.Router();
const propertyListController = require('../../controllers/UserController/saleController');

// Existing routes:
router.get('/all', propertyListController.getAllProperties);
router.get('/active', propertyListController.getActiveProperties);
router.get('/sold', propertyListController.getSoldProperties);

// New routes for sale and rent:
router.get('/sale', propertyListController.getSaleProperties);
router.get('/rent', propertyListController.getRentProperties);

module.exports = router;