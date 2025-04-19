const dbPromise = require('../../database/db');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcrypt');
const saltRounds = parseInt(process.env.BCRYPT_SALT_ROUNDS) || 10; // Use environment variable

const authController = {
  login: async (req, res) => {
    const requestId = uuidv4();
    try {
      const db = await dbPromise;
      const { username, password, redirect } = req.body;

      // Validate input
      if (!username || !password) {
        console.log(`[${requestId}] Missing credentials`);
        return res.render('login', {
          error: 'Username and PASSWORD are required',
          redirect,
          inputValues: { username }
        });
      }

      const trimmedUsername = username.trim();
      const trimmedEmail = trimmedUsername.toLowerCase();
      const trimmedPhone = trimmedUsername.replace(/[\s-()+]/g, ''); // Normalize phone
      console.log(`[${requestId}] Attempting login for:`, trimmedUsername);

      // Database query with specific columns
      const [results] = await db.query(
        'SELECT Id, Username, Password, role FROM Users WHERE Username = ? OR EMAIL = ? OR phone = ? LIMIT 1',
        [trimmedUsername, trimmedEmail, trimmedPhone]
      );

      console.log(`[${requestId}] Query returned ${results.length} rows`);

      // Handle no user found
      if (results.length === 0) {
        console.log(`[${requestId}] No matching user found`);
        return res.render('login', {
          error: 'Invalid username or PASSWORD',
          redirect,
          inputValues: { username: trimmedUsername }
        });
      }

      const user = results[0];

      // Validate user object structure
      if (!user?.Id || !user?.Password) {
        console.error(`[${requestId}] Malformed user data:`, user);
        return res.render('login', {
          error: 'Account configuration error - contact support',
          redirect
        });
      }

      // PASSWORD verification
      const isPasswordValid = await bcrypt.compare(password, user.Password);
      if (!isPasswordValid) {
        console.log(`[${requestId}] Invalid PASSWORD attempt`);
        return res.render('login', {
          error: 'Invalid username or PASSWORD',
          redirect,
          inputValues: { username: trimmedUsername }
        });
      }

      // Session regeneration with promise
      await new Promise((resolve, reject) => {
        req.session.regenerate((err) => {
          if (err) return reject(err);
          resolve();
        });
      });

      // Set session data
      req.session.user = {
        id: user.Id,
        username: user.Username,
        role: user.role
      };

      // Update user sessions table
      await db.query(
        `INSERT INTO user_sessions (session_id, user_id, expires)
          VALUES (?, ?, UNIX_TIMESTAMP() + ?)
          ON DUPLICATE KEY UPDATE
            expires = VALUES(expires)`,
        [
          req.sessionID,
          user.Id,
          Math.floor(req.session.cookie.maxAge / 1000)
        ]
      );

      // Update last login
      await db.query(
        'UPDATE Users SET last_login = NOW() WHERE Id = ?',
        [user.Id]
      );

      // Enhanced redirect validation
      const validRedirects = ['/user_dashboard', '/admin/settings', '/profile'];
      let redirectPath = user.role === 'admin' ? '/admin/settings' : '/user_dashboard';
      if (redirect && /^\/[a-zA-Z0-9\/_-]+$/.test(redirect) && !redirect.includes('..')) {
        redirectPath = redirect;
      }

      // Final redirect with session save
      req.session.save((err) => {
        if (err) {
          console.error(`[${requestId}] Session save failed:`, err);
          return res.render('login', {
            error: 'Login failed - please try again',
            redirect
          });
        }
        console.log(`[${requestId}] Successful login for user ${user.Id}`);
        res.redirect(redirectPath);
      });
    } catch (error) {
      console.error(`[${requestId}] Unexpected system error:`, error);
      res.render('login', {
        error: 'A system error occurred - please try again',
        redirect: req.body.redirect
      });
    }
  },

  signup: async (req, res) => {
    try {
      const { redirect } = req.query; // Support redirect query param
      res.render('signup', { inputValues: {}, redirect: redirect || '' });
    } catch (err) {
      console.error('Signup page render failed:', err);
      res.status(500).render('error', {
        message: 'Server error - please try again',
        user: null
      });
    }
  },

  register: async (req, res) => {
    const requestId = uuidv4();
    try {
      const db = await dbPromise;
      const { username, email, password, phone, dob } = req.body;

      // Enhanced validation
      const errors = [];
      if (!username || username.length < 3) errors.push('Username must be at least 3 characters');
      if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        errors.push('Valid email required');
      }
      if (!password || password.length < 8) errors.push('PASSWORD must be at least 8 characters');
      if (!phone || !/^\+?[\d\s-]{10,15}$/.test(phone)) {
        errors.push('Valid phone number required (e.g., +1234567890 or 123-456-7890)');
      }
      const dobDate = new Date(dob);
      const today = new Date();
      const minDate = new Date(today.getFullYear() - 120, today.getMonth(), today.getDate());
      if (!dob || isNaN(dobDate.getTime()) || dobDate > today || dobDate < minDate) {
        errors.push('Valid date of birth required (must be between 120 years ago and today)');
      }

      if (errors.length > 0) {
        console.log(`[${requestId}] Validation errors:`, errors);
        return res.render('signup', {
          error: errors.join(', '),
          inputValues: { username, email, phone, dob }
        });
      }

      // Normalize inputs
      const trimmedUsername = username.trim();
      const trimmedEmail = email.toLowerCase().trim();
      const normalizedPhone = phone.trim().replace(/[\s-()+]/g, '');

      // Check for existing user
      const [existingUsers] = await db.query(
        'SELECT Id FROM Users WHERE Username = ? OR EMAIL = ? OR phone = ? LIMIT 1',
        [trimmedUsername, trimmedEmail, normalizedPhone]
      );

      if (existingUsers.length > 0) {
        console.log(`[${requestId}] Duplicate credentials found`);
        return res.render('signup', {
          error: 'Username, email or phone already in use',
          inputValues: { username, email, phone, dob }
        });
      }

      // Create new user with transaction
      const connection = await db.getConnection();
      try {
        await connection.beginTransaction();
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        await connection.query(
          `INSERT INTO Users (
            Username, EMAIL, Password, phone, Date_of_Birth, role, created_at
          ) VALUES (?, ?, ?, ?, ?, 'user', NOW())`,
          [
            trimmedUsername,
            trimmedEmail,
            hashedPassword,
            normalizedPhone,
            new Date(dob).toISOString().split('T')[0]
          ]
        );
        await connection.commit();
      } catch (error) {
        await connection.rollback();
        throw error;
      } finally {
        connection.release();
      }

      // Success
      await new Promise((resolve, reject) => {
        req.session.regenerate((err) => {
          if (err) return reject(err);
          resolve();
        });
      });

      req.session.success = 'Registration successful! Please login';
      console.log(`[${requestId}] New user registered: ${trimmedUsername}`);
      res.redirect('/login');
    } catch (error) {
      console.error(`[${requestId}] Registration failed:`, error);
      res.render('signup', {
        error: 'Registration failed - please try again',
        inputValues: req.body
      });
    }
  },

  logout: async (req, res) => {
    const requestId = uuidv4();
    if (!req.session.user) {
      return res.redirect('/login');
    }

    const userId = req.session.user.id;
    const sessionId = req.sessionID;

    await new Promise((resolve, reject) => {
      req.session.destroy((err) => {
        if (err) return reject(err);
        resolve();
      });
    });

    try {
      const db = await dbPromise;
      await db.query('DELETE FROM user_sessions WHERE session_id = ?', [sessionId]);
    } catch (dbErr) {
      console.error(`[${requestId}] Failed to delete session:`, dbErr);
    }

    res.clearCookie(req.session.cookie.name || 'connect.sid'); // Use configured cookie name
    console.log(`[${requestId}] User ${userId} logged out`);
    res.redirect('/login');
  },

  cleanupSessions: async () => {
    const requestId = uuidv4();
    try {
      const db = await dbPromise;
      const [expiredResult] = await db.query(
        'DELETE FROM user_sessions WHERE expires < UNIX_TIMESTAMP()'
      );
      const [orphanedResult] = await db.query(
        `DELETE s FROM user_sessions s
          LEFT JOIN Users u ON s.user_id = u.Id
          WHERE u.Id IS NULL`
      );
      console.log(`[${requestId}] Session cleanup completed: ${expiredResult.affectedRows} expired, ${orphanedResult.affectedRows} orphaned sessions removed`);
    } catch (err) {
      console.error(`[${requestId}] Cleanup failed:`, err);
    }
  }
};

module.exports = authController;