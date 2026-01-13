const fs = require('fs');
const path = require('path');
const SESSIONS_FILE = path.join(__dirname, 'sessions.json');

function migrate() {
  try {
    const s = fs.readFileSync(SESSIONS_FILE, 'utf8');
    const raw = JSON.parse(s || '{}');
    let migrated = false;
    Object.keys(raw).forEach(k => {
      if (Array.isArray(raw[k])) {
        raw[k] = { sessions: raw[k], profile: { username: k, email: k } };
        migrated = true;
        console.log('Will migrate user', k);
      }
    });
    if (migrated) {
      fs.writeFileSync(SESSIONS_FILE, JSON.stringify(raw, null, 2), 'utf8');
      console.log('Migration complete.');
    } else {
      console.log('No migration needed.');
    }
  } catch (e) {
    console.error('Migration failed', e && e.message);
    process.exit(1);
  }
}

migrate();
