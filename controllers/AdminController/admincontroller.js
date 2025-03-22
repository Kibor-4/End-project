const db = require("../../database/db");

const adminController = {
  createAdmin: async (req, res) => {
    const { name, email, password } = req.body;

    try {
      // Check if the email already exists
      const [existingUser] = await db.query("SELECT * FROM users WHERE email = ?", [email]);
      if (existingUser.length > 0) {
        return res.status(400).json({ message: "Email already exists" });
      }

      // Insert the new admin with plain text password (INSECURE)
      const [result] = await db.query(
        "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, 'admin')",
        [name, email, password] // Store password in plain text
      );

      // Return the newly created admin
      const newAdmin = {
        id: result.insertId,
        name,
        email,
        role: "admin",
      };

      res.status(201).json({ message: "Admin created successfully", newAdmin });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: "Server error", error });
    }
  },
};

module.exports = adminController;