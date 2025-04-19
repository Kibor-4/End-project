const db = require('../../database/db');
const logger = require('../../router/AuthRoutes/logger'); // Assuming you have a logger setup



const analyticsController = {
  getAnalytics: async (req, res) => {
    try {
      // 1. Validate time period parameters (if any)
      const { startDate, endDate } = validateDateRange(req.query);

      // 2. Execute queries in parallel for better performance
      const [salesData, userActivityData] = await Promise.all([
        getSalesData(startDate, endDate),
        getUserActivityData(startDate, endDate)
      ]);

      // 3. Format response data
      const response = {
        sales: formatSalesData(salesData),
        userActivity: formatUserActivityData(userActivityData),
        meta: {
          generatedAt: new Date().toISOString(),
          timeRange: { startDate, endDate }
        }
      };

      // 4. Cache control headers
      res.set('Cache-Control', 'public, max-age=300'); // 5 minute cache

      // 5. Render view or send JSON based on accept header
      return req.accepts('html')
        ? res.render('analytics', response)
        : res.json(response);

    } catch (error) {
      logger.error('Analytics error:', {
        error: error.message,
        stack: error.stack,
        requestId: req.requestId
      });

      return res.status(500).render('error', {
        message: 'Unable to load analytics',
        statusCode: 500,
        user: req.user
      });
    }
  }
};

// Helper functions
function validateDateRange(query) {
  const defaultDays = 30;
  let { startDate, endDate } = query;

  endDate = endDate ? new Date(endDate) : new Date();
  startDate = startDate ? new Date(startDate) : new Date();
  startDate.setDate(endDate.getDate() - defaultDays);

  // Validate dates are within reasonable bounds
  if (isNaN(startDate.getTime())) {
    startDate = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
  }
  if (isNaN(endDate.getTime())) {
    endDate = new Date();
  }

  return { startDate, endDate };
}

async function getSalesData(startDate, endDate) {
  try {
    const [rows] = await db.query(`
      SELECT
        DATE(created_at) AS date,
        SUM(amount) AS total_sales,
        COUNT(*) AS transaction_count
      FROM transactions
      WHERE type = 'sale'
        AND created_at BETWEEN ? AND ?
      GROUP BY DATE(created_at)
      ORDER BY date ASC
    `, [startDate, endDate]);
    return rows;
  } catch (error) {
    logger.error('Error fetching sales data:', { error: error.message, stack: error.stack });
    throw error;
  }
}

async function getUserActivityData(startDate, endDate) {
  try {
    const [rows] = await db.query(`
      SELECT
        DATE(login_time) AS date,
        COUNT(DISTINCT user_id) AS active_users,
        COUNT(*) AS total_logins
      FROM user_sessions
      WHERE login_time BETWEEN ? AND ?
      GROUP BY DATE(login_time)
      ORDER BY date ASC
    `, [startDate, endDate]);
    return rows;
  } catch (error) {
    logger.error('Error fetching user activity data:', { error: error.message, stack: error.stack });
    throw error;
  }
}

function formatSalesData(data) {
  if (!data || !data.length) {
    return [];
  }
  return data.map(row => ({
    date: row.date.toISOString().split('T')[0],
    totalSales: parseFloat(row.total_sales),
    transactionCount: row.transaction_count
  }));
}

function formatUserActivityData(data) {
  if (!data || !data.length) {
    return [];
  }
  return data.map(row => ({
    date: row.date.toISOString().split('T')[0],
    activeUsers: row.active_users,
    totalLogins: row.total_logins
  }));
}

module.exports = analyticsController;