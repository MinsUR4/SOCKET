// server.js
const WebSocket = require('ws');

// Start a WebSocket server on port 8080
const wss = new WebSocket.Server({ port: 8080 });

wss.on('connection', (ws) => {
  console.log('Client connected');

  // Optional: send a message to client when connected
  ws.send('Hello client! You are connected.');

  ws.on('message', (message) => {
    console.log('Received from client:', message);
  });

  ws.on('close', () => {
    console.log('Client disconnected');
  });
});

console.log('WebSocket server running on ws://localhost:8080');
