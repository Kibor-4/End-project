const express = require('express');
const router = express.Router();
const homeController = require('../../controllers/UserController/indexController');

router.get('/', homeController.renderIndex);
router.post('/redirect', homeController.handleRedirect);
router.get('/sell', homeController.renderSell);
router.get('/rent', homeController.renderRent);
router.get('/buy', homeController.renderBuy);

module.exports = router;