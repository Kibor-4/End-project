const getPool = require('../../database/db');

async function fetchProperties(req, res, queryBase, queryParamsBase = []) {
try {
const pool = await getPool;
let query = queryBase;
let queryParams = [...queryParamsBase];

const queryParameters = {
  location: req.query.location,
  house_type: req.query.house_type,
  min_price: req.query.min_price,
  max_price: req.query.max_price,
  bedrooms: req.query.bedrooms,
  bathrooms: req.query.bathrooms,
  property_type: req.query.property_type,
};

// Build dynamic query based on provided filters
for (const key in queryParameters) {
  if (queryParameters[key]) {
    query += ` AND ${key} ${key === 'location' ? 'LIKE' : '='} ?`;
    queryParams.push(key === 'location' ? `%${queryParameters[key]}%` : queryParameters[key]);
  }
}

const [rows] = await pool.query(query, queryParams);

// Parse images safely
const properties = rows.map((property) => {
  try {
    return {
      ...property,
      images: JSON.parse(property.images),
    };
  } catch (error) {
    console.error('Error parsing images:', error);
    return {
      ...property,
      images: [], // Default to empty array if parsing fails
    };
  }
});

// Render the page with properties (even if empty)
res.render('sale', {
  properties: properties,
  query: req.query,
  req: req,
  message: properties.length === 0 ? 'No properties found.' : null, // Optional message
});
} catch (error) {
console.error('Error fetching properties:', error);
res.status(500).send('Server error');
}
}

async function getAllProperties(req, res) {
await fetchProperties(req, res, 'SELECT * FROM Properties WHERE 1=1');
}

async function getActiveProperties(req, res) {
await fetchProperties(req, res, 'SELECT * FROM Properties WHERE status = ?', ['Active']);
}

async function getSoldProperties(req, res) {
await fetchProperties(req, res, 'SELECT * FROM Properties WHERE status = ?', ['Sold']);
}

async function getSaleProperties(req, res) {
await fetchProperties(req, res, 'SELECT * FROM Properties WHERE property_type = ?', ['sale']);
}

async function getRentProperties(req, res) {
await fetchProperties(req, res, 'SELECT * FROM Properties WHERE property_type = ?', ['rent']);
}

module.exports = {
getAllProperties,
getActiveProperties,
getSoldProperties,
getSaleProperties,
getRentProperties,
};