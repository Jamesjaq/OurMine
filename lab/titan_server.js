const http = require('http');
const crypto = require('crypto');

const PORT = 9000;
let db = {
  users: [{ id: 1, username: 'admin', role: 'superuser', token: 'secret_token_999' }],
  ledger: { balance: 15000000, currency: 'USD', vault: 'SECURE_RESERVE_ALPHA' }
};

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  
  if (url.pathname === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'HEALTHY', system: 'TITAN_ENTERPRISE_GATEWAY', version: '4.2.1' }));
  } else if (url.pathname === '/api/v1/auth') {
    const user = url.searchParams.get('user');
    const pass = url.searchParams.get('pass');
    if (user === 'admin' && pass === 'admin123') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true, token: 'JWT_TITAN_SUPER_SECRET_ACCESS' }));
    } else {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: false, error: 'Unauthorized Access' }));
    }
  } else if (url.pathname === '/api/v1/ledger') {
    const authHeader = req.headers['authorization'];
    if (authHeader && authHeader.includes('JWT_TITAN_SUPER_SECRET_ACCESS')) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true, ledger: db.ledger }));
    } else {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: false, error: 'Forbidden: Missing Sovereign Token' }));
    }
  } else {
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Endpoint not found' }));
  }
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`[TITAN_TARGET] Complex enterprise server running on port ${PORT}`);
});
