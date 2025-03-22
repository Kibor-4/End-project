const dbPromise = require('../../database/db');

const authController = {
    login: async (req, res) => {
        try {
            const db = await dbPromise;
            const { username, password, redirect } = req.body;

            // Validate input
            if (!username || !password) {
                return res.render('login', { error: 'Username and password are required', redirect });
            }

            // Query the database for the user
            const query = 'SELECT * FROM Users WHERE Username = ? OR EMAIL = ? OR phone = ?';
            const [results] = await db.query(query, [username, username, username]);

            // Check if the user exists
            if (results.length === 0) {
                return res.render('login', { error: 'Invalid username or password', redirect });
            }

            const user = results[0];

            // Compare plain text passwords (INSECURE - use hashed passwords in production)
            if (password === user.Password) {
                // Set session data
                req.session.userId = user.Id;
                req.session.role = user.role;

                // Redirect based on role
                if (user.role === 'admin') {
                    return res.redirect('/admin/settings'); // Redirect admin to /about
                } else if (user.role === 'user') {
                    return res.redirect('/admin/settings'); // Redirect user to /all
                } else {
                    return res.redirect('/'); // Default redirect for other roles
                }
            } else {
                return res.render('login', { error: 'Invalid username or password', redirect });
            }
        } catch (error) {
            console.error('Login error:', error);
            return res.render('login', { error: 'An error occurred during login', redirect: req.body.redirect });
        }
    },

    signup: async (req, res) => {
        try {
            res.render('signup');
        } catch (err) {
            console.log(err);
            res.status(500).send('error');
        }
    },

    register: async (req, res) => {
        try {
            const db = await dbPromise;
            const { username, email, password, phone, dob } = req.body;

            // Validate input
            if (!username || !email || !password || !phone || !dob) {
                return res.render('signup', { error: 'All fields are required' });
            }

            // Store password in plain text (INSECURE - use hashed passwords in production)
            const query = 'INSERT INTO Users (Username, EMAIL, Password, phone, Date_of_Birth, role) VALUES (?, ?, ?, ?, ?, ?)';
            await db.query(query, [username, email, password, phone, dob, 'user']);

            res.redirect('/login');
        } catch (error) {
            console.error('Signup error:', error);
            res.render('signup', { error: 'An error occurred during signup' });
        }
    },

    logout: (req, res) => {
        req.session.destroy((err) => {
            if (err) {
                console.error('Logout error:', err);
            }
            res.redirect('/login');
        });
    },
};

module.exports = authController;