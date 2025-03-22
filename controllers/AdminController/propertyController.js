const db = require('../../database/db'); // Import the MySQL connection

const propertyController = {
  // Render the properties page
  getProperties: async (req, res) => {
    try {
      // Fetch all properties from the database
      const [properties] = await db.query('SELECT * FROM Properties');
      res.render('properties', { properties }); // Render the properties view with data
    } catch (error) {
      console.error(error);
      res.status(500).send('Internal Server Error');
    }
  },
};

module.exports = propertyController;