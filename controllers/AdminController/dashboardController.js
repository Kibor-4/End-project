const db = require('../../database/db'); // Import the MySQL connection

const dashboardController = {
  // Render the dashboard page
  getDashboard: async (req, res) => {
    try {
      // Fetch total properties
      const [properties] = await db.query('SELECT COUNT(*) AS totalProperties FROM Properties');
      const totalProperties = properties[0].totalProperties;

      // Fetch total users
      const [users] = await db.query('SELECT COUNT(*) AS totalUsers FROM Users');
      const totalUsers = users[0].totalUsers;

      // Fetch total transactions
      const [transactions] = await db.query('SELECT COUNT(*) AS totalTransactions FROM transactions');
      const totalTransactions = transactions[0].totalTransactions;

      // Render the dashboard view with data
      res.render('dashboard', { totalProperties, totalUsers, totalTransactions });
    } catch (error) {
      console.error(error);
      res.status(500).send('Internal Server Error');
    }
  },
};

module.exports = dashboardController;