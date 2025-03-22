const getPool = require('../database/db');

const isAuthenticated = async (req, res, next) => {
    console.log('Session in isAuthenticated:', req.session);

    if (req.session && req.session.userId) {
        try {
            const pool = await getPool; // Resolve the pool
            const [rows] = await pool.query('SELECT * FROM Users WHERE id = ?', [req.session.userId]);

            if (rows && rows.length > 0) {
                req.user = rows[0]; // Attach the user to the request object
                return next(); // Proceed to the next middleware/route handler
            } else {
                console.log("User not found from session ID");
                // Store the intended URL before redirecting
                req.session.redirectTo = req.originalUrl;
                return res.redirect("/login");
            }
        } catch (err) {
            console.error("Error fetching user from database:", err);
            // Store the intended URL before redirecting
            req.session.redirectTo = req.originalUrl;
            return res.redirect("/login");
        }
    } else {
        console.log('User not authenticated');
        // Store the intended URL before redirecting
        req.session.redirectTo = req.originalUrl;
        return res.redirect('/login');
    }
};

module.exports = isAuthenticated;