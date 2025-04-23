const bcrypt = require('bcrypt');
const { validationResult } = require('express-validator');
const passport = require('passport');
const { v4: uuidv4 } = require('uuid');
const db = require('../../database/db');

const authController = {
    // Login - GET
    getLogin: (req, res) => {
        res.render('login', {
            title: 'Login',
            message: req.flash('error'),
            user: req.user || null
        });
    },

    // Login - POST
    postLogin: passport.authenticate('local', {
        successRedirect: 'dashboard',
        failureRedirect: 'login',
        failureFlash: true
    }),

    // Register - GET
    getRegister: (req, res) => {
        res.render('register', {
            title: 'Register',
            message: req.flash('error'),
            user: req.user || null
        });
    },

    // Register - POST
    postRegister: async (req, res) => {
        const { username, email, password, confirmPassword } = req.body;
        
        if (password !== confirmPassword) {
            req.flash('error', 'Passwords do not match.');
            return res.redirect('signup');
        }

        try {
            const existingUser = await db.query('SELECT Id FROM Users WHERE email = ?', [email]);
            if (existingUser.length > 0) {
                req.flash('error', 'Email already in use.');
                return res.redirect('signup');
            }

            const hashedPassword = await bcrypt.hash(password, 10);
            await db.query(
                'INSERT INTO Users (username, email, password) VALUES (?, ?, ?)',
                [username, email, hashedPassword]
            );

            req.flash('success', 'Registration successful! Please log in.');
            res.redirect('login');
        } catch (error) {
            console.error('Registration error:', error);
            req.flash('error', 'Registration failed. Please try again.');
            res.redirect('/auth/register');
        }
    },

    // Logout - GET
    getLogout: (req, res, next) => {
        req.logout((err) => {
            if (err) {
                console.error('Logout error:', err);
                return next(err);
            }
            req.flash('success', 'Logged out successfully');
            res.redirect('login');
        });
    },

    // Forgot Password - GET
    getForgotPassword: (req, res) => {
        res.render('forgot-password', {
            title: 'Forgot Password',
            message: req.flash('info'),
            error: req.flash('error'),
            user: req.user || null
        });
    },

    // Forgot Password - POST
    postForgotPassword: async (req, res) => {
        const { email } = req.body;
        try {
            const users = await db.query('SELECT Id, email FROM Users WHERE email = ?', [email]);
            if (users.length === 0) {
                req.flash('error', 'No user found with that email address.');
                return res.redirect('/auth/forgot-password');
            }

            const resetToken = uuidv4();
            await db.query(
                'UPDATE Users SET resetToken = ?, resetTokenExpiry = DATE_ADD(NOW(), INTERVAL 1 HOUR) WHERE Id = ?',
                [resetToken, users[0].Id]
            );

            console.log('Password reset token generated for:', email, 'Token:', resetToken);
            req.flash('info', 'A password reset link has been sent to your email address (check console).');
            res.redirect('/auth/forgot-password');
        } catch (error) {
            console.error('Forgot password error:', error);
            req.flash('error', 'An error occurred while processing your request.');
            res.redirect('/auth/forgot-password');
        }
    },

    // Reset Password - GET
    getResetPassword: async (req, res) => {
        const { token } = req.params;
        try {
            const users = await db.query(
                'SELECT Id FROM Users WHERE resetToken = ? AND resetTokenExpiry > NOW()',
                [token]
            );
            if (users.length === 0) {
                req.flash('error', 'Invalid or expired reset token.');
                return res.redirect('/auth/forgot-password');
            }
            res.render('reset-password', {
                title: 'Reset Password',
                token,
                error: req.flash('error'),
                user: req.user || null
            });
        } catch (error) {
            console.error('Get reset password error:', error);
            req.flash('error', 'An error occurred while verifying the reset token.');
            res.redirect('/auth/forgot-password');
        }
    },

    // Reset Password - POST
    postResetPassword: async (req, res) => {
        const { token, password, confirmPassword } = req.body;
        if (password !== confirmPassword) {
            return res.render('reset-password', {
                title: 'Reset Password',
                token,
                error: 'Passwords do not match.',
                user: req.user || null
            });
        }

        try {
            const users = await db.query(
                'SELECT Id FROM Users WHERE resetToken = ? AND resetTokenExpiry > NOW()',
                [token]
            );
            if (users.length === 0) {
                req.flash('error', 'Invalid or expired reset token.');
                return res.redirect('/auth/forgot-password');
            }

            const hashedPassword = await bcrypt.hash(password, 10);
            await db.query(
                'UPDATE Users SET Password = ?, resetToken = NULL, resetTokenExpiry = NULL WHERE Id = ?',
                [hashedPassword, users[0].Id]
            );

            req.flash('success', 'Password reset successfully. You can now log in.');
            res.redirect('login');
        } catch (error) {
            console.error('Reset password error:', error);
            req.flash('error', 'An error occurred while resetting your password.');
            res.redirect(`/auth/reset-password/${token}`);
        }
    }
};

module.exports = authController;