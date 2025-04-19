const mysql = require('mysql2/promise');
require('dotenv').config();
const logger = require('../router/AuthRoutes/logger'); // Assuming you have a logger

class Database {
  constructor() {
    this.validateConfig();
    this.pool = this.createPool();
    this.testConnection();
    this.setupEventListeners();
  }

  validateConfig() {
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
  }

  createPool() {
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
      timezone: 'Z', // Use UTC
      charset: 'utf8mb4_unicode_ci',
      ssl: this.getSSLConfig(),
      typeCast: this.typeCast,
      supportBigNumbers: true,
      bigNumberStrings: true
    };

    if (process.env.NODE_ENV !== 'production') {
      config.debug = process.env.DB_DEBUG === 'true';
      config.insecureAuth = true;
    }

    return mysql.createPool(config);
  }

  getSSLConfig() {
    if (process.env.DB_SSL !== 'true') return false;

    return {
      rejectUnauthorized: process.env.NODE_ENV === 'production',
      ca: process.env.DB_SSL_CA,
      cert: process.env.DB_SSL_CERT,
      key: process.env.DB_SSL_KEY
    };
  }

  typeCast(field, next) {
    if (field.type === 'TINY' && field.length === 1) {
      return field.string() === '1'; // Convert TINYINT(1) to boolean
    }
    if (field.type === 'DATE') {
      return field.string(); // Return raw date string
    }
    return next();
  }

  async testConnection() {
    try {
      const conn = await this.pool.getConnection();
      await conn.ping();
      conn.release();
      logger.info('Database connection established successfully');
    } catch (err) {
      logger.error('Database connection failed', { error: err.message });
      process.exit(1);
    }
  }

  setupEventListeners() {
    this.pool.on('connection', (connection) => {
      logger.debug('New database connection established');
    });

    this.pool.on('acquire', (connection) => {
      logger.debug('Connection %d acquired', connection.threadId); // Changed from logger.silly
    });

    this.pool.on('release', (connection) => {
      logger.debug('Connection %d released', connection.threadId); // Changed from logger.silly
    });

    this.pool.on('enqueue', () => {
      logger.warn('Waiting for available connection slot');
    });
  }

  async query(sql, params) {
    try {
      const [rows] = await this.pool.query(sql, params);
      return rows;
    } catch (err) {
      logger.error('Database query error', {
        sql: sql,
        params: params,
        error: err.message
      });
      throw err;
    }
  }

  async transaction(callback) {
    const conn = await this.pool.getConnection();
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
}

module.exports = new Database();