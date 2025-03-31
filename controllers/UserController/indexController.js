const express = require('express');

function renderIndex(req, res) {
  res.render('index');
}

function handleRedirect(req, res) {
  const action = req.body.action;
  const location = req.body.location;
  const propertyType = req.body.propertyType;

  let redirectURL = '';

  switch (action) {
    case 'sell':
      redirectURL = `/sale?location=${location}&propertyType=${propertyType}`;
      break;
    case 'rent':
      redirectURL = `/rent?location=${location}&propertyType=${propertyType}`;
      break;
    case 'buy':
      redirectURL = `/all?location=${location}&propertyType=${propertyType}`;
      break;
    default:
      res.send('Invalid action');
      return;
  }

  res.redirect(redirectURL);
}

function renderSell(req, res) {
  const location = req.query.location;
  const propertyType = req.query.propertyType;
  res.render('all', { location: location, propertyType: propertyType });
}

function renderRent(req, res) {
  const location = req.query.location;
  const propertyType = req.query.propertyType;
  res.render('rent', { location: location, propertyType: propertyType });
}

function renderBuy(req, res) {
  const location = req.query.location;
  const propertyType = req.query.propertyType;
  res.render('sale', { location: location, propertyType: propertyType });
}

module.exports = {
  renderIndex,
  handleRedirect,
  renderSell,
  renderRent,
  renderBuy,
};