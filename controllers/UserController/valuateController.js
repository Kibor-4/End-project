const model = require('../../model');
const labelEncoder = require('../../labelencoder');

function getValuationPage(req, res) {
  res.render('valuate');
}

function postValuation(req, res) {
  const { location, house_type, bedrooms, bathrooms } = req.body;

  const locationEncoded = labelEncoder.locationEncode(location);
  const houseTypeEncoded = labelEncoder.propertyTitleEncode(house_type);

  const features = [houseTypeEncoded, locationEncoded, parseFloat(bedrooms), parseFloat(bathrooms)];
  const prediction = model.predict(features);

  res.render('valuate', { prediction: prediction });
}

module.exports = {
  getValuationPage,
  postValuation,
};