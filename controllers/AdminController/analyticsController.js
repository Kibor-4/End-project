const db = require('../../database/db'); // Import your database connection

const analyticsController = {
  // Render the Analytics page
  getAnalytics: async (req, res) => {
    try {
      // Fetch sales data from the database (example query)
      const [salesData] = await db.query(`
        SELECT DATE(created_at) AS date, SUM(amount) AS total_sales
        FROM transactions
        WHERE type = 'sale'
        GROUP BY DATE(created_at)
      `);

      // Fetch user activity data from the database (example query)
      const [userActivityData] = await db.query(`
        SELECT DATE(login_time) AS date, COUNT(*) AS logins
        FROM user_sessions
        GROUP BY DATE(login_time)
      `);

      // Format data for the charts
      const salesChartData = salesData.map(row => ({
        date: row.date,
        totalSales: row.total_sales,
      }));

      const userActivityChartData = userActivityData.map(row => ({
        date: row.date,
        logins: row.logins,
      }));

      // Render the analytics page with the data
      res.render('analytics', {
        salesChartData,
        userActivityChartData,
      });
    } catch (error) {
      console.error('Error fetching analytics data:', error);
      res.status(500).send('Internal Server Error');
    }
  },
};

module.exports = analyticsController;