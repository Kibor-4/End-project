const getPool = require('../../database/db');

async function getPropertyDetails(req, res) {
  const propertyId = req.params.id;

  try {
    const pool = await getPool;

    const [propertyRows] = await pool.query(
      `
        SELECT 
          id, sqft, price, lot_size, location, images, house_type, 
          description, created_at, bedrooms, bathrooms
        FROM Properties
        WHERE id = ?
      `,
      [propertyId]
    );

    if (propertyRows.length === 0) {
      return res.status(404).send('Property not found.');
    }

    const property = propertyRows[0];
    property.images = property.images ? JSON.parse(property.images) : [];
    property.price = parseFloat(property.price);

    const [reviewRows] = await pool.query(
      `
        SELECT reviews.*, users.username 
        FROM reviews 
        JOIN users ON reviews.user_id = users.id 
        WHERE property_id = ? 
        ORDER BY created_at DESC
      `,
      [propertyId]
    );

    const user = req.session.user;
    res.render('property-details', { property, reviews: reviewRows, user: user });
  } catch (err) {
    console.error('Error fetching property details:', err);
    res.status(500).send('Server error occurred while fetching property details.');
  }
}

async function addPropertyReview(req, res) {
  const propertyId = req.params.id;
  const { rating, comment } = req.body;
  const userId = req.session.userId;

  try {
    const pool = await getPool;
    await pool.query('INSERT INTO reviews (property_id, user_id, rating, comment) VALUES (?, ?, ?, ?)', [
      propertyId,
      userId,
      rating,
      comment,
    ]);
    res.redirect(`/property/${propertyId}`);
  } catch (err) {
    console.error('Error adding review:', err);
    res.status(500).send('Server error occurred while adding review.');
  }
}

module.exports = {
  getPropertyDetails,
  addPropertyReview,
};