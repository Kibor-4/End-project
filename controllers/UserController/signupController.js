const getPool = require('../../database/db');
const { validationResult } = require('express-validator');

async function submitUser(req, res) {
  try {
    const { username, email, password } = req.body;

    const pool = await getPool;
    await pool.query('INSERT INTO Users (Username, EMAIL, Password) VALUES (?, ?, ?)', [
      username,
      email,
      password, // Storing password in plain text (VERY INSECURE)
    ]);

    res.redirect('/login');
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
}

module.exports = {
  submitUser,
};