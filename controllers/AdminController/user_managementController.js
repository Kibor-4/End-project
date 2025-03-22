const db = require('../../database/db'); // Import the MySQL connection

const userController = {
  // Render the user management page with pagination
  getUsers: async (req, res) => {
    try {
      const page = parseInt(req.query.page) || 1; // Default to page 1
      const limit = parseInt(req.query.limit) || 10; // Default to 10 users per page
      const offset = (page - 1) * limit;

      // Fetch paginated users, reflecting the schema
      const [users] = await db.query(
        'SELECT Id,Username, EMAIL, Date_of_Birth, Password, phone, Profile_picture, role, id FROM Users LIMIT ? OFFSET ?',
        [limit, offset]
      );

      // Fetch total number of users for pagination
      const [totalUsers] = await db.query('SELECT COUNT(*) AS total FROM Users');
      const total = totalUsers[0].total;
      const totalPages = Math.ceil(total / limit);

      // Render the view with pagination data
      res.render('users_management', {
        users,
        page,
        limit,
        total,
        totalPages,
      });
    } catch (error) {
      console.error('Error fetching users:', error);
      res.status(500).send('Internal Server Error');
    }
  },

  // Handle user deletion
  deleteUser: async (req, res) => {
    try {
      const userId = req.params.id;

      // Check if the user exists
      const [user] = await db.query('SELECT Username FROM Users WHERE id = ?', [userId]); //Only select username to reduce data transfer.
      if (user.length === 0) {
        return res.status(404).send('User not found.');
      }

      // Delete the user
      await db.query('DELETE FROM Users WHERE id = ?', [userId]);
      res.redirect('/admin/users'); // Redirect back to the user management page
    } catch (error) {
      console.error('Error deleting user:', error);
      res.status(500).send('Internal Server Error');
    }
  },

  // Handle user editing
  editUser: async (req, res) => {
    const connection = await db.getConnection();
    try {
      await connection.beginTransaction(); // Start a transaction

      const userId = req.params.id;
      const { Username, EMAIL, role, Date_of_Birth, phone, Profile_picture } = req.body;

      // Input validation
      if (!Username || !EMAIL || !role) {
        return res.status(400).send('Username, email, and role are required.');
      }

      if (isNaN(userId)) {
        return res.status(400).send('Invalid user ID.');
      }

      // Update the user's information, reflecting the schema
      await connection.query(
        'UPDATE Users SET Username = ?, EMAIL = ?, role = ?, Date_of_Birth = ?, phone = ?, Profile_picture = ? WHERE id = ?',
        [Username, EMAIL, role, Date_of_Birth, phone, Profile_picture, userId]
      );

      await connection.commit(); // Commit the transaction
      res.redirect('/admin/users'); // Redirect back to the user management page
    } catch (error) {
      await connection.rollback(); // Rollback the transaction on error
      console.error('Error updating user:', error);
      res.status(500).send('Internal Server Error');
    } finally {
      connection.release(); // Release the connection
    }
  },
};

module.exports = userController;