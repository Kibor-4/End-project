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

            // Render the dashboard view with data, including user from session
            res.render('../../views/Admin/dashboard.ejs', { 
                user: req.session.user, // Add user from session
                totalProperties, 
                totalUsers, 
                totalTransactions 
            });
        } catch (error) {
            console.error('Dashboard error:', error);
            res.status(500).render('error', { 
                message: 'Internal Server Error', 
                user: req.session.user || null 
            });
        }
    },
};

module.exports = dashboardController;