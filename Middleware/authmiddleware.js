const db = require('../database/db'); // Import the Database instance

// Initialize pool at startup (it's already initialized when the db instance is created)
let dbPool = db.pool; // Access the pool property of the imported object

// Initialize database connection (already done in db.js)
(async () => {
  try {
    // No need to call getPool() again, the pool is already in dbPool
    console.log('Database pool already initialized');
  } catch (err) {
    console.error('Error (should not happen if db.js initialized correctly):', err);
    process.exit(1);
  }
})();

const isAuthenticated = async (req, res, next) => {
  // 1. Check session exists
  if (!req.session?.userId) {
    return redirectToLogin(req, res);
  }

  // 2. Verify user in database
  try {
    const rows = await db.query( // Use the query method of the imported db object
      'SELECT id, email, username, role FROM Users WHERE id = ?',
      [req.session.userId]
    );

    if (!rows?.length) {
      req.session.destroy(); // Clear invalid session
      return redirectToLogin(req, res);
    }

    // 3. Attach user to request
    req.user = rows[0];
    return next();

  } catch (err) {
    console.error('Authentication error:', err);
    return res.status(500).json({
      error: 'Authentication service unavailable',
      requestId: req.requestId
    });
  }
};

// Helper function for login redirect
function redirectToLogin(req, res) {
  req.session.redirectTo = req.originalUrl;

  // Handle API vs web requests
  if (req.xhr || req.headers.accept?.includes('application/json')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  return res.redirect('/login');
}

module.exports = isAuthenticated;