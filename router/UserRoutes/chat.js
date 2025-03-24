const express = require('express');
const { getChatHistory, getConversations } = require('../../controllers/UserController/chatController');

const router = express.Router();

router.get('/chat-history', getChatHistory);
router.get('/conversations', getConversations);

module.exports = router;