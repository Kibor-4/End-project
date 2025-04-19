const express = require('express');
const router = express.Router();
const propertyListController = require('../../controllers/UserController/saleController');

// Existing routes:
router.get('/User/all', propertyListController.getAllProperties);
router.get('/User/active', propertyListController.getActiveProperties);
router.get('/User/sold', propertyListController.getSoldProperties);

// New routes for sale and rent:
router.get('/User/sale', propertyListController.getSaleProperties);
router.get('/User/rent', propertyListController.getRentProperties);

module.exports = router;