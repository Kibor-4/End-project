const express = require('express');
const { getChatHistory, getConversations } = require('../../controllers/UserController/chatController');

const router = express.Router();

router.get('/User/chat-history', getChatHistory);
router.get('/User/conversations', getConversations);

module.exports = router;