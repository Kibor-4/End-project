const dbPromise = require('../../database/db');
const { v4: uuidv4 } = require('uuid');

const authController = {
    login: async (req, res) => {
        const requestId = uuidv4();
        try {
            const db = await dbPromise;
            const { username, password, redirect } = req.body;

            if (!username || !password) {
                console.log(`[${requestId}] Login failed: missing username or password, sessionID: ${req.sessionID}`);
                return res.render('login', { error: 'Username and password are required', redirect, inputValues: { username } });
            }

            const [results] = await db.query('SELECT * FROM Users WHERE Username = ? OR EMAIL = ? OR phone = ?', [username, username, username]);

            if (results.length === 0) {
                console.log(`[${requestId}] Login failed: invalid username or password, sessionID: ${req.sessionID}`);
                return res.render('login', { error: 'Invalid username or password', redirect, inputValues: { username } });
            }

            const user = results[0];

            if (password === user.Password) {
                console.log(`[${requestId}] Session ID before regenerate: ${req.sessionID}`);

                req.session.regenerate(async (err) => {
                    if (err) {
                        console.error(`[${requestId}] Session regeneration error:`, err);
                        return res.render('login', { error: 'Login failed - please try again', redirect });
                    }
                    console.log(`[${requestId}] Session ID after regenerate: ${req.sessionID}`);

                    req.session.user = { id: user.Id, username: user.Username, role: user.role };

                    try {
                        const result = await db.query(
                            'UPDATE user_sessions SET user_id = ? WHERE session_id = ?',
                            [user.Id, req.sessionID]
                        );
                        console.log(`[${requestId}] Database update result:`, result);
                        await db.query(
                            'UPDATE Users SET last_login = NOW() WHERE Id = ?',
                            [user.Id]
                        );

                        let redirectPath = '/user_dashboard';
                        if (user.role === 'admin') redirectPath = '/admin/settings';
                        if (redirect && redirect.startsWith('/') && !redirect.includes('//')) redirectPath = redirect;

                        console.log(`[${requestId}] User ${user.Id} logged in successfully, sessionID: ${req.sessionID}`);
                        return res.redirect(redirectPath);
                    } catch (dbError) {
                        console.error(`[${requestId}] Database update error:`, dbError);
                        return res.render('login', { error: 'Login failed - database error', redirect });
                    }
                });
            } else {
                console.log(`[${requestId}] Login failed: invalid password, sessionID: ${req.sessionID}`);
                return res.render('login', { error: 'Invalid username or password', redirect, inputValues: { username } });
            }
        } catch (error) {
            console.error(`[${requestId}] Login error:`, error);
            return res.render('login', { error: 'An error occurred during login', redirect: req.body.redirect });
        }
    },

    signup: async (req, res) => {
        try {
            res.render('signup', { inputValues: {} });
        } catch (err) {
            console.error('Signup page error:', err);
            res.status(500).render('error', { message: 'Server error', user: null });
        }
    },

    register: async (req, res) => {
        const requestId = uuidv4();
        try {
            const db = await dbPromise;
            const { username, email, password, phone, dob } = req.body;

            const errors = [];
            if (!username) errors.push('Username is required');
            if (!email || !email.includes('@')) errors.push('Valid email is required');
            if (!password || password.length < 6) errors.push('Password must be at least 6 characters');
            if (!phone) errors.push('Phone number is required');
            if (!dob || isNaN(new Date(dob))) errors.push('Valid date of birth is required');

            if (errors.length > 0) {
                console.log(`[${requestId}] Registration failed due to input validation errors.`);
                return res.render('signup', { error: errors.join(', '), inputValues: { username, email, phone, dob } });
            }

            const [existingUsers] = await db.query('SELECT Id FROM Users WHERE Username = ? OR EMAIL = ? OR phone = ?', [username, email, phone]);

            if (existingUsers.length > 0) {
                console.log(`[${requestId}] Registration failed: Username, email or phone already in use.`);
                return res.render('signup', { error: 'Username, email or phone already in use', inputValues: { username, email, phone, dob } });
            }

            const query = `INSERT INTO Users (Username, EMAIL, Password, phone, Date_of_Birth, role, created_at) VALUES (?, ?, ?, ?, ?, 'user', NOW())`;
            await db.query(query, [username, email, password, phone, dob]);

            req.session.regenerate(() => {
                req.session.success = 'Registration successful! Please login';
                console.log(`[${requestId}] User ${username} registered successfully.`);
                res.redirect('/login');
            });
        } catch (error) {
            console.error(`[${requestId}] Signup error:`, error);
            res.render('signup', { error: 'An error occurred during registration', inputValues: req.body });
        }
    },

    logout: (req, res) => {
        const requestId = uuidv4();
        if (!req.session.user) {
            return res.redirect('/login');
        }

        const userId = req.session.user.id;
        req.session.destroy((err) => {
            if (err) {
                console.error(`[${requestId}] Logout error:`, err);
                return res.status(500).render('error', { message: 'Logout failed', user: null });
            }

            res.clearCookie('sessionId');
            console.log(`[${requestId}] User ${userId} logged out successfully, sessionID: ${req.sessionID}`);
            res.redirect('/login');
        });
    },

    cleanupSessions: async () => {
        const requestId = uuidv4();
        try {
            const db = await dbPromise;
            await db.query('DELETE FROM user_sessions WHERE expires < UNIX_TIMESTAMP()');
            await db.query(`DELETE s FROM user_sessions s LEFT JOIN Users u ON s.user_id = u.Id WHERE s.user_id IS NOT NULL AND u.Id IS NULL`);
            console.log(`[${requestId}] Session cleanup completed.`);
        } catch (err) {
            console.error(`[${requestId}] Session cleanup error:`, err);
        }
    }
};

module.exports = authController;