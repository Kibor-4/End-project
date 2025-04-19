const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const db = require('../../database/db'); // Adjust the path as needed

passport.use(new LocalStrategy({ usernameField: 'email' }, async (email, password, done) => {
  try {
    const [users] = await db.query('SELECT id, name, email, password, role FROM users WHERE email = ?', [email]);

    if (users.length === 0) {
      return done(null, false, { message: 'Incorrect email or password' });
    }

    const user = users[0];

    const passwordMatch = await bcrypt.compare(password, user.password);

    if (passwordMatch) {
      return done(null, user);
    } else {
      return done(null, false, { message: 'Incorrect email or password' });
    }
  } catch (error) {
    return done(error);
  }
}));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const [users] = await db.query('SELECT id, name, email, role FROM users WHERE id = ?', [id]);
    if (users.length > 0) {
      return done(null, users[0]);
    } else {
      return done(null, false);
    }
  } catch (error) {
    return done(error);
  }
});

module.exports = passport;