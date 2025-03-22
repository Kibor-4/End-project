const getPool = require('../../database/db');
const multer = require('multer');
const path = require('path');

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'Public/uploads/'); // Set the upload directory
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  },
});

const upload = multer({ storage: storage });

async function getUserProfile(req, res) {
  try {
    const pool = await getPool;
    const userId = req.session.userId;

    const [userResult] = await pool.query('SELECT * FROM Users WHERE id = ?', [userId]);
    console.log('User result:', userResult);

    if (!userResult[0]) {
      console.log('No user found with ID:', userId);
      return res.redirect('/login');
    }

    const user = {
      Username: userResult[0].Username,
      email: userResult[0].email,
      phone: userResult[0].phone,
      profile_picture: userResult[0].profile_picture,
    };

    res.render('profile', { user: user });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server Error');
  }
}

async function updateUserProfile(req, res) {
  try {
    const pool = await getPool;
    const userId = req.session.userId;
    const { username, email, phone } = req.body;
    let profilePicturePath = req.file ? '/Public/uploads/' + req.file.filename : null;

    // If a new picture wasn't uploaded, keep the old one.
    if (!profilePicturePath) {
      const [oldPicture] = await pool.query('SELECT profile_picture FROM Users WHERE id = ?', [userId]);
      if (oldPicture[0] && oldPicture[0].profile_picture) {
        profilePicturePath = oldPicture[0].profile_picture;
      }
    }

    await pool.query('UPDATE Users SET Username = ?, email = ?, phone = ?, profile_picture = ? WHERE id = ?', [
      username,
      email,
      phone,
      profilePicturePath,
      userId,
    ]);

    // Fetch the updated user data
    const [updatedUserResult] = await pool.query('SELECT * FROM Users WHERE id = ?', [userId]);

    if (!updatedUserResult[0]) {
      return res.status(500).send('Failed to retrieve updated user data.');
    }

    const updatedUser = {
      Username: updatedUserResult[0].Username,
      email: updatedUserResult[0].email,
      phone: updatedUserResult[0].phone,
      profile_picture: updatedUserResult[0].profile_picture,
    };

    res.render('profile', { user: updatedUser }); // Render with updated data
  } catch (err) {
    console.error(err);
    res.status(500).send('Server Error');
  }
}

module.exports = {
  getUserProfile,
  updateUserProfile: [upload.single('profilePicture'), updateUserProfile], //using array to add middleware to controller.
};