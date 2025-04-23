// signupController.js
const db = require('../../database/db'); // Changed to match app.js
const bcrypt = require('bcrypt');

exports.renderSignupPage = (req, res) => {
    res.render('signup', {
        title: 'Sign Up',
        errors: req.flash('error') || [],
        formData: {}
    });
};

exports.submitUser = async (req, res) => {
    try {
        const { username, email, phone, dob, password, confirmPassword } = req.body;
        const errors = [];

        if (!username || !email || !phone || !dob || !password || !confirmPassword) {
            errors.push({ msg: 'All fields are required' });
        }
        if (password !== confirmPassword) {
            errors.push({ msg: 'Passwords do not match' });
        }

        if (errors.length > 0) {
            return res.status(400).render('signup', {
                title: 'Sign Up',
                errors,
                formData: { username, email, phone, dob }
            });
        }

        const existingUsers = await db.query( // Changed to db.query
            'SELECT * FROM Users WHERE Username = ? OR EMAIL = ?',
            [username, email]
        );

        if (existingUsers.length > 0) {
            errors.push({ field: 'username', msg: 'Username or email already exists' });
            return res.status(409).render('signup', {
                title: 'Sign Up',
                errors,
                formData: { username, email, phone, dob }
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        await db.query( // Changed to db.query
            'INSERT INTO Users (Username, EMAIL, phone, Date_of_Birth, Password, role) VALUES (?, ?, ?, ?, ?, ?)',
            [username, email, phone, dob, hashedPassword, 'user']
        );

        req.flash('success', 'Registration successful! Please log in.');
        res.redirect('/auth/login');
    } catch (error) {
        console.error('Error during signup:', error);
        res.status(500).render('signup', {
            title: 'Sign Up',
            errors: [{ msg: 'Something went wrong during signup' }],
            formData: req.body
        });
    }
};

exports.loginUser = async (req, res) => {
    try {
        const { username, password } = req.body;

        const users = await db.query( // Changed to db.query
            'SELECT * FROM Users WHERE Username = ?',
            [username]
        );

        if (users.length === 0) {
            req.flash('error', 'Invalid username or password');
            return res.redirect('/auth/login');
        }

        const user = users[0];

        const passwordMatch = await bcrypt.compare(password, user.Password);

        if (!passwordMatch) {
            req.flash('error', 'Invalid username or password');
            return res.redirect('/auth/login');
        }

        req.session.userId = user.Id;
        req.session.username = user.Username;
        res.redirect('/user/dashboard');
    } catch (error) {
        console.error('Error during login:', error);
        req.flash('error', 'Something went wrong during login');
        res.redirect('/auth/login');
    }
};

module.exports = exports;