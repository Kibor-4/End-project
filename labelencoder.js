// Assuming you have the same unique values for 'PropertyTitle' and 'Location' as in your training data
const propertyTitles = ["apartment", "townhouse", "bungalow", "villa", "condo", "duplex", "mansion", "other"]; // Add all your property titles
const locations = ["Nairobi", "Mombasa", "Kisumu", "Nakuru"]; // Add all your locations

const propertyTitleMap = {};
const locationMap = {};

propertyTitles.forEach((title, index) => {
  propertyTitleMap[title] = index;
});

locations.forEach((location, index) => {
  locationMap[location] = index;
});

function propertyTitleEncode(title) {
  return propertyTitleMap[title] !== undefined ? propertyTitleMap[title] : -1; // -1 for unknown
}

function locationEncode(location) {
  return locationMap[location] !== undefined ? locationMap[location] : -1; // -1 for unknown
}

module.exports = {
  propertyTitleEncode,
  locationEncode,
};