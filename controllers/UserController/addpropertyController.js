const getPool = require('../../database/db');
const { body, validationResult } = require('express-validator');

// Validation middleware
const validateProperty = [
body('property_type').isIn(['sale', 'rent']).withMessage('Property type must be sale or rent'),
body('location').notEmpty().withMessage('Location is required'),
body('house_type').notEmpty().withMessage('House type is required'),
body('price').isNumeric().withMessage('Price must be a number'),
body('sqft').optional().isInt({ min: 0 }).withMessage('Square footage must be a positive integer'),
body('bedrooms').optional().isInt({ min: 0 }).withMessage('Bedrooms must be a positive integer'),
body('bathrooms').optional().isInt({ min: 0 }).withMessage('Bathrooms must be a positive integer'),
body('lot_size').optional().isInt({ min: 0 }).withMessage('Lot size must be a positive integer'),
body('description').optional().isString().withMessage('Description must be a string'),
// Add more validation rules as needed
];

const submitProperty = async (req, res) => {
try {
// Validate request body
const errors = validationResult(req);
if (!errors.isEmpty()) {
    return res.status(400).render('upload', { errors: errors.array(), formData: req.body }); // Render upload with errors
}

// Check if user is authenticated
if (!req.user || !req.user.id) {
    return res.status(401).send('Unauthorized: User ID not found.');
}

const userId = req.user.id;
const { property_type, location, house_type, sqft, bedrooms, bathrooms, lot_size, price, description } = req.body;

// Handle file uploads
const images = req.files && req.files.length > 0
    ? req.files.map(file => '/Public/Uploads/uploads/' + file.filename)
    : [];

// Insert property into the database
const pool = await getPool;
await pool.query(
    'INSERT INTO Properties (property_type, location, house_type, sqft, bedrooms, bathrooms, lot_size, price, description, images, user_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
    [property_type, location, house_type, sqft, bedrooms, bathrooms, lot_size, price, description, JSON.stringify(images), userId]
);

// Redirect based on property type
if (property_type === 'sale') {
    res.redirect('/sale'); // Redirect to sale page
} else if (property_type === 'rent') {
    res.redirect('/rent'); // Redirect to rent page
} else {
    res.status(400).send('Invalid property type.');
}
} catch (error) {
console.error('Error adding property:', error);
res.status(500).render('upload', { errors: [{ msg: 'Error adding property.' }], formData: req.body }); // Render upload with error
}
};

module.exports = { submitProperty, validateProperty };