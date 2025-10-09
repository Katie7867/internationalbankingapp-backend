const http = require('http');

//ensure testing is performed only against systems you control or have explicit permission to test
for (let i = 1; i <= 210; i++) {
  //observe rate limits and avoid causing denial-of-service; this script intentionally exceeds typical limits
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
      //record response codes to verify rate-limiter and error handling
      console.log(i, '→', res.statusCode);
    }
  );

  req.on('error', (err) => {
    console.log(i, '→ ERROR', err.message);
  });

  //do not use real user credentials when testing; use clearly invalid or test accounts
  req.write(JSON.stringify({
    username: 'fake',
    password: 'wrong',
    accountNumber: '12345678'
  }));
  req.end();
}
