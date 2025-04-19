const db = require("../../database/db");
const bcrypt = require('bcrypt');
const { validationResult } = require('express-validator');

const adminController = {
  createAdmin: async (req, res) => {
    // 1. Input validation
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, email, password } = req.body;

    try {
      // 2. Check for existing user (case-insensitive)
      const [existingUser] = await db.query(
        "SELECT id FROM users WHERE LOWER(email) = LOWER(?)", 
        [email]
      );

      if (existingUser.length > 0) {
        return res.status(409).json({ 
          message: "Email already exists",
          code: "EMAIL_EXISTS"
        });
      }

      // 3. Hash password with bcrypt
      const saltRounds = 10;
      const hashedPassword = await bcrypt.hash(password, saltRounds);

      // 4. Create admin with transaction
      await db.beginTransaction();
      
      try {
        const [result] = await db.query(
          `INSERT INTO users 
          (name, email, password, role, created_at) 
          VALUES (?, ?, ?, 'admin', NOW())`,
          [name, email, hashedPassword]
        );

        await db.commit();

        // 5. Return response without sensitive data
        const newAdmin = {
          id: result.insertId,
          name,
          email,
          role: "admin",
          createdAt: new Date().toISOString()
        };

        return res.status(201).json({ 
          success: true,
          message: "Admin created successfully",
          data: newAdmin
        });

      } catch (txError) {
        await db.rollback();
        throw txError;
      }

    } catch (error) {
      console.error("Admin creation error:", error);
      return res.status(500).json({ 
        success: false,
        message: "Internal server error",
        code: "SERVER_ERROR",
        systemMessage: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  },
};

module.exports = adminController;