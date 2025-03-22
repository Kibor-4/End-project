const getPool = require('../../database/db');

const getDashboard = async (req, res) => {
    try {
        // Check if user is authenticated
        if (!req.user || !req.user.id) {
            return res.status(401).redirect('/login');
        }

        const userId = req.user.id;

        // Fetch user details
        const pool = await getPool();
        const [user] = await pool.query('SELECT name FROM Users WHERE id = ?', [userId]);

        // Fetch dashboard stats
        const [stats] = await pool.query(`
            SELECT 
                COUNT(*) AS totalProperties,
                SUM(views) AS totalViews,
                (SELECT COUNT(*) FROM Reviews WHERE property_id IN (SELECT id FROM Properties WHERE user_id = ?)) AS totalReviews
            FROM Properties
            WHERE user_id = ?
        `, [userId, userId]);

        // Fetch user properties with reviews
        const [properties] = await pool.query(`
            SELECT 
                Properties.id,
                Properties.title,
                Properties.location,
                Properties.price,
                Properties.views,
                Properties.image,
                (SELECT JSON_ARRAYAGG(JSON_OBJECT('comment', Reviews.comment, 'user', Users.name))
                    FROM Reviews
                    INNER JOIN Users ON Reviews.user_id = Users.id
                    WHERE Reviews.property_id = Properties.id
                ) AS reviews
            FROM Properties
            WHERE user_id = ?
        `, [userId]);

        // Parse reviews from JSON string to array
        properties.forEach(property => {
            property.reviews = JSON.parse(property.reviews || '[]');
        });

        // Render the dashboard view with data
        res.render('dashboard', {
            user: user[0],
            stats: stats[0],
            properties: properties
        });
    } catch (error) {
        console.error('Error fetching dashboard data:', error);
        res.status(500).send('Internal Server Error');
    }
};

module.exports = {
    getDashboard
};