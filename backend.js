const socket = new WebSocket("ws://matOS.web.com");

socket.addEventListener("open", (event) => {
        console.log("WebSocket connection established!");
});

socket.addEventListener("error", (event) => {
        console.error("WebSocket connection error:", event);
});

socket.addEventListener("close", (event) => {
        console.log("WebSocket connection closed:", event);
});

function sendTextOverWebSocket(text) {
    if (socket.readyState === WebSocket.OPEN) {
        socket.send(text);
    } else {
        console.error("WebSocket connection not open!");
    }
}
