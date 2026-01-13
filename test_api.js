const http = require('http');

function post(path, data) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(data);
    const options = {
      hostname: 'localhost',
      port: 4001,
      path,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
      },
    };
    const req = http.request(options, (res) => {
      let out = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => out += chunk);
      res.on('end', () => resolve({ status: res.statusCode, body: out }));
    });
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

(async () => {
  try {
    console.log('Registering user test_auto');
    const r1 = await post('/api/register', { username: 'test_auto', password: 'pass123' });
    console.log('REGISTER', r1.status, r1.body);

    console.log('Logging in user test_auto');
    const r2 = await post('/api/login', { username: 'test_auto', password: 'pass123' });
    console.log('LOGIN', r2.status, r2.body);
  } catch (e) {
    console.error('ERROR', e && e.message);
    process.exit(1);
  }
})();
