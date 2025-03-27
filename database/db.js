const mysql = require('mysql2/promise');
require('dotenv').config();

// Validate minimum required environment variables
if (!process.env.DB_HOST || !process.env.DB_USER || !process.env.DB_NAME) {
  throw new Error('Missing required database configuration in .env file');
}

// MySQL 5.7 compatible configuration
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD || null, // Explicit null for empty password
  connectionLimit: parseInt(process.env.DB_POOL_LIMIT) || 10,
  waitForConnections: true,
  queueLimit: 0,
  insecureAuth: process.env.NODE_ENV !== 'production', // Allow insecure auth in development
  connectTimeout: 10000, // 10 seconds connection timeout
  // MySQL 5.7 specific auth plugin configuration
  authPlugins: {
    mysql_clear_password: () => () => Buffer.from((process.env.DB_PASSWORD || '') + '\0')
  }
});

// Test the connection on startup
pool.getConnection()
  .then(connection => {
    console.log('Successfully connected to MySQL database');
    connection.release();
  })
  .catch(err => {
    console.error('Database connection failed:', err.message);
    process.exit(1);
  });

module.exports = pool;