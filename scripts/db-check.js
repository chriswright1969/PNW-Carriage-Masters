import { db, DB_PATH, adminCount, listMedia } from '../src/db.js';

const pages = db.prepare('SELECT slug, updated_at FROM pages').all();
console.log('DB:', DB_PATH);
console.log('Active admins:', adminCount());
console.log('Pages:', pages);
console.log('Media items:', listMedia().length);
