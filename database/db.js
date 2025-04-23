// database/db.js
const mysql = require('mysql2/promise');
require('dotenv').config();
const logger = require('../router/AuthRoutes/logger');

let pool;

const initializePool = async () => {
    if (pool) {
        logger.info('Reusing existing database pool');
        return pool;
    }

    // Validate configuration
    const requiredVars = ['DB_HOST', 'DB_USER', 'DB_NAME'];
    const missingVars = requiredVars.filter(v => !process.env[v]);
    if (missingVars.length > 0) {
        const errorMsg = `Missing required DB config: ${missingVars.join(', ')}`;
        logger.error(errorMsg);
        throw new Error(errorMsg);
    }

    if (process.env.NODE_ENV === 'production' && !process.env.DB_PASSWORD) {
        logger.error('DB_PASSWORD is required in production');
        throw new Error('Database password required in production');
    }

    // Pool configuration
    const config = {
        host: process.env.DB_HOST,
        user: process.env.DB_USER,
        database: process.env.DB_NAME,
        password: process.env.DB_PASSWORD,
        port: parseInt(process.env.DB_PORT) || 3306,
        connectionLimit: parseInt(process.env.DB_POOL_LIMIT) || 10,
        waitForConnections: true,
        queueLimit: parseInt(process.env.DB_QUEUE_LIMIT) || 0,
        connectTimeout: 10000,
        timezone: 'Z',
        charset: 'utf8mb4_unicode_ci',
        ssl: process.env.DB_SSL === 'true' ? {
            rejectUnauthorized: process.env.NODE_ENV === 'production',
            ca: process.env.DB_SSL_CA,
            cert: process.env.DB_SSL_CERT,
            key: process.env.DB_SSL_KEY
        } : false,
        typeCast: (field, next) => {
            if (field.type === 'TINY' && field.length === 1) {
                return field.string() === '1';
            }
            if (field.type === 'DATE') {
                return field.string();
            }
            return next();
        },
        supportBigNumbers: true,
        bigNumberStrings: true
    };

    if (process.env.NODE_ENV !== 'production') {
        config.debug = process.env.DB_DEBUG === 'true';
        config.insecureAuth = true;
    }

    try {
        pool = await mysql.createPool(config);
        const conn = await pool.getConnection();
        await conn.ping();
        conn.release();
        logger.info('Database connection established successfully');

        // Setup event listeners
        pool.on('connection', () => {
            logger.debug('New database connection established');
        });
        pool.on('acquire', (connection) => {
            logger.debug(`Connection ${connection.threadId} acquired`);
        });
        pool.on('release', (connection) => {
            logger.debug(`Connection ${connection.threadId} released`);
        });
        pool.on('enqueue', () => {
            logger.warn('Waiting for available connection slot');
        });

        logger.info('Database pool initialized');
        return pool;
    } catch (err) {
        logger.error(`Failed to initialize database pool: ${err.message}`);
        throw err;
    }
};

// Export pool as a promise
module.exports = {
    pool: initializePool(),
    // Optional: Export query method for convenience
    query: async (sql, params) => {
        const poolInstance = await initializePool();
        try {
            const [rows] = await poolInstance.query(sql, params);
            return rows;
        } catch (err) {
            logger.error('Database query error', {
                sql,
                params,
                error: err.message
            });
            throw err;
        }
    },
    // Optional: Export transaction method
    transaction: async (callback) => {
        const poolInstance = await initializePool();
        const conn = await poolInstance.getConnection();
        try {
            await conn.beginTransaction();
            const result = await callback(conn);
            await conn.commit();
            return result;
        } catch (err) {
            await conn.rollback();
            throw err;
        } finally {
            conn.release();
        }
    }
};