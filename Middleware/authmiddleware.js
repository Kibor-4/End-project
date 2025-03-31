const getPool = require('../database/db');

const isAuthenticated = async (req, res, next) => {
    if (req.session && req.session.userId) {
        try {
            const [rows] = await (await getPool).query('SELECT * FROM Users WHERE id = ?', [req.session.userId]);

            if (rows && rows.length > 0) {
                req.user = rows[0];
                return next();
            }
        } catch (err) {
            console.error("Error fetching user from database:", err);
        }
    }

    req.session.redirectTo = req.originalUrl;
    return res.redirect('/login');
};

module.exports = isAuthenticated;