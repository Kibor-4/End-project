const db = require('../../database/db'); // Import the MySQL connection

const transactionController = {
  // Render the transactions page
  getTransactions: async (req, res) => {
    try {
      // Fetch all transactions from the database
      const [transactions] = await db.query('SELECT * FROM transactions');
      res.render('transactions', { transactions }); // Render the transactions view with data
    } catch (error) {
      console.error(error);
      res.status(500).send('Internal Server Error');
    }
  },
};

module.exports = transactionController;