import 'dotenv/config';
import { query } from './db.js';
import { hashPassword } from './utils/password.js';

const ACCOUNTS = [
  { u: 'VIP-BY-ZYE',     p: 'HYRINJECT'    },
  { u: 'ZYE-INJECT',     p: 'ZYEHYPER'     },
  { u: 'KAIZYE-INJECT',  p: 'ZYESETTINGS'  },
  { u: 'ZYE-CITER',      p: 'ZYECITEDZ'    },
  { u: 'GACOR-BY-ZYE',   p: 'INJECTZYE'    },
  { u: 'ZYE-VIP-INJECT', p: 'VIPINJECTZYE' }
];

for (const acc of ACCOUNTS) {
  const hash = await hashPassword(acc.p);
  await query(
    `INSERT INTO users (username, password_hash, role)
     VALUES ($1, $2, 'user')
     ON CONFLICT (username) DO UPDATE SET password_hash = EXCLUDED.password_hash`,
    [acc.u, hash]
  );
  console.log('seeded:', acc.u);
}
console.log('done.');
process.exit(0);