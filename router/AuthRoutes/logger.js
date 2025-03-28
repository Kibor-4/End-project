// logger.js

const fs = require('fs');
const path = require('path');

const logDirectory = path.join(__dirname, 'logs'); // Create a 'logs' directory in the same folder as logger.js

// Ensure the log directory exists
if (!fs.existsSync(logDirectory)) {
  fs.mkdirSync(logDirectory);
}

function getTimestamp() {
  return new Date().toISOString();
}

function log(level, message) {
  const timestamp = getTimestamp();
  const logMessage = `[${timestamp}] [${level.toUpperCase()}] ${message}\n`;

  const logFilePath = path.join(logDirectory, 'app.log'); // Log file name

  fs.appendFile(logFilePath, logMessage, (err) => {
    if (err) {
      console.error('Error writing to log file:', err);
    }
  });
}

function info(message) {
  log('info', message);
}

function warn(message) {
  log('warn', message);
}

function error(message) {
  log('error', message);
}

function debug(message) {
  log('debug', message);
}

module.exports = {
  info,
  warn,
  error,
  debug,
};