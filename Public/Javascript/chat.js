const chatMessages = document.getElementById('chat-messages');
const messageInput = document.getElementById('message-input');
const sendButton = document.getElementById('send-button');

// Connect to WebSocket server
const ws = new WebSocket('ws://localhost:3000');

ws.onopen = () => {
console.log('Connected to the WebSocket server');
};

ws.onmessage = (event) => {
const data = JSON.parse(event.data);

if (data.type === 'history') {
    // Load chat history
    data.data.forEach((msg) => {
        addMessage(msg.sender, msg.message);
    });
} else {
    // Add new message
    addMessage(data.sender, data.text);
}
};

// Function to add a message to the chat
function addMessage(sender, message) {
const messageElement = document.createElement('div');
messageElement.classList.add('message', sender);
messageElement.textContent = message;
chatMessages.appendChild(messageElement);
chatMessages.scrollTop = chatMessages.scrollHeight; // Auto-scroll to the bottom
}

// Send message on button click
sendButton.addEventListener('click', () => {
const message = messageInput.value.trim();
if (message) {
    const data = {
        sender: 'buyer',
        text: message,
    };
    ws.send(JSON.stringify(data)); // Send message to the server
    addMessage('buyer', message); // Display the message locally
    messageInput.value = ''; // Clear input field
}
});

// Send message on pressing Enter key
messageInput.addEventListener('keypress', (e) => {
if (e.key === 'Enter') {
    sendButton.click();
}
});