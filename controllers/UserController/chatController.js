const db = require('../../database/db');

const getChatHistory = (req, res) => {
const { userId, otherUserId } = req.query;

if (!userId || !otherUserId) {
return res.status(400).json({ message: 'User ID and Other User ID are required' });
}

db.query(
`SELECT m.*, u.profile_pic AS sender_profile_pic 
    FROM messages m
    JOIN users u ON m.sender_id = u.id
    WHERE (m.sender_id = ? AND m.receiver_id = ?) 
    OR (m.sender_id = ? AND m.receiver_id = ?) 
    ORDER BY m.created_at ASC`,
[userId, otherUserId, otherUserId, userId],
(err, results) => {
    if (err) {
        console.error('Error fetching chat history:', err);
        return res.status(500).json({ message: 'Error fetching chat history' });
    }
    res.status(200).json(results);
}
);
};

const getConversations = (req, res) => {
const { userId } = req.query;

if (!userId) {
return res.status(400).json({ message: 'User ID is required' });
}

db.query(
`SELECT u.id, u.username, u.profile_pic, MAX(m.created_at) AS latest_message_time
    FROM users u
    JOIN messages m ON u.id = m.sender_id OR u.id = m.receiver_id
    WHERE (m.sender_id = ? OR m.receiver_id = ?) AND u.id != ?
    GROUP BY u.id, u.username, u.profile_pic
    ORDER BY latest_message_time DESC`,
[userId, userId, userId],
(err, results) => {
    if (err) {
        console.error('Error fetching conversations:', err);
        return res.status(500).json({ message: 'Error fetching conversations' });
    }
    res.status(200).json(results);
}
);
};

module.exports = { getChatHistory, getConversations };