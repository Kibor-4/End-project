const express = require('express');
const transactionController = require('../../controllers/AdminController/transactionsController');

const router = express.Router();

// Route to render the transactions page
router.get('/admin/transactions', transactionController.getTransactions);

module.exports = router;