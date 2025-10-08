const http = require('http');

for (let i = 1; i <= 210; i++) {
  const req = http.request(
    {
      hostname: 'localhost',
      port: 4000,
      path: '/api/auth/login',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      }
    },
    (res) => {
      console.log(i, '→', res.statusCode);
    }
  );

  req.on('error', (err) => {
    console.log(i, '→ ERROR', err.message);
  });

  req.write(JSON.stringify({
    username: 'fake',
    password: 'wrong',
    accountNumber: '12345678'
  }));
  req.end();
}