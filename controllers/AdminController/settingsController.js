const db = require('../../database/db'); // Import the MySQL connection

const settingsController = {
    // Render the settings page
    getSettings: async (req, res) => {
        try {
            const user = req.session.user; // Get the user from the session

            if (!user) {
                return res.redirect('/login'); // Redirect to login if the user is not logged in
            }

            res.render('Adminsettings', { user }); // Pass the user object to the template
        } catch (error) {
            console.error(error);
            res.status(500).send('Internal Server Error');
        }
    },

    // Handle creating a new admin
    createAdmin: async (req, res) => {
        try {
            if (req.session.user.role !== 'admin') {
                return res.status(403).json({ success: false, message: "Unauthorized"});
            }

            const { name, email, password } = req.body;

            // Insert the new admin into the database (no hashing)
            await db.query(
                'INSERT INTO Users (Username, EMAIL, Password, role) VALUES (?, ?, ?, "admin")',
                [name, email, password]
            );

            res.json({ success: true, message: 'Admin created successfully!' });
        } catch (error) {
            console.error(error);
            res.status(500).json({ success: false, message: 'Error creating admin' });
        }
    },
};

module.exports = settingsController;