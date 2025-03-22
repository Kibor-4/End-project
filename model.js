function predict(features) {
    // Your generated Decision Tree logic here
    // Example:
    if (features[0] <= 10) {
      if (features[1] <= 5) {
        return 150000;
      } else {
        return 200000;
      }
    } else {
      return 300000;
    }
  }
  
  module.exports = {
    predict: predict,
  };