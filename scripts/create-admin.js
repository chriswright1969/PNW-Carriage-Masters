import bcrypt from 'bcryptjs';
import validator from 'validator';
import { createAdmin, getAdminByEmail, adminCount, DB_PATH } from '../src/db.js';

const [,, emailArg, passwordArg, firstNameArg, lastNameArg] = process.argv;

if (!emailArg || !passwordArg) {
  console.log('Usage: npm run create-admin -- <email> <password> [firstName] [lastName]');
  process.exit(1);
}

const email = String(emailArg).trim().toLowerCase();
const password = String(passwordArg);

if (!validator.isEmail(email)) {
  console.error('Invalid email');
  process.exit(1);
}
if (password.length < 10) {
  console.error('Password must be 10+ characters');
  process.exit(1);
}

const exists = getAdminByEmail(email);
if (exists) {
  console.error('Admin already exists for that email');
  process.exit(1);
}

const hash = bcrypt.hashSync(password, 12);
createAdmin({
  email,
  password_hash: hash,
  first_name: firstNameArg || '',
  last_name: lastNameArg || ''
});

console.log(`Created admin: ${email}`);
console.log(`DB: ${DB_PATH}`);
console.log(`Active admins: ${adminCount()}`);
