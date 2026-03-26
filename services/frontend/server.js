const http = require("http");

const server = http.createServer((req, res) => {
  res.writeHead(200, { "Content-Type": "text/html" });
  res.end(`
    <html>
      <head><title>CyberSentinel</title></head>
      <body>
        <h1>CyberSentinel Frontend Running</h1>
        <p>Frontend minimal sans Vite.</p>
      </body>
    </html>
  `);
});

server.listen(3000, "0.0.0.0", () => {
  console.log("Frontend running on port 3000");
});