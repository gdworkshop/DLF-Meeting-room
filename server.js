const express = require('express'), crypto = require('crypto'), path = require('path'), { Pool } = require('pg');
const ROOMS = ['Marina', 'Elliot', 'Kovalam', 'Auroville', 'Pebble', 'Coral'];
const TZ = process.env.APP_TZ || 'Asia/Kolkata';
const SECRET = process.env.SECRET || 'dev-secret-change-me';
const BOSS = (process.env.ADMIN_EMAIL || '').trim().toLowerCase();
const local = /localhost|127\.0\.0\.1/.test(process.env.DATABASE_URL || '');
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: local ? false : { rejectUnauthorized: false } });
const q = (s, p) => pool.query(s, p);
const scrypt = (pw, salt) => new Promise((ok, no) => crypto.scrypt(pw, salt, 64, (e, k) => e ? no(e) : ok(k.toString('hex'))));
const sign = s => crypto.createHmac('sha256', SECRET).update(s).digest('base64url');
const mk = email => { const b = Buffer.from(JSON.stringify({ e: email, x: Date.now() + 7 * 864e5 })).toString('base64url'); return b + '.' + sign(b); };
function ver(t) {
  if (!t) return null; const [b, s] = t.split('.'); if (!b || !s) return null;
  const a = Buffer.from(sign(b)), c = Buffer.from(s);
  if (a.length !== c.length || !crypto.timingSafeEqual(a, c)) return null;
  try { const o = JSON.parse(Buffer.from(b, 'base64url')); return o.x > Date.now() ? o.e : null; } catch { return null; }
}
function now() {
  const p = {}; new Intl.DateTimeFormat('en-GB', { timeZone: TZ, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' })
    .formatToParts(new Date()).forEach(x => p[x.type] = x.value);
  return { d: `${p.year}-${p.month}-${p.day}`, t: `${p.hour}:${p.minute}` };
}
const app = express(); app.set('trust proxy', 1); app.use(express.json({ limit: '20kb' }));
const w = f => (req, res) => f(req, res).catch(e => { console.error(e); res.status(500).json({ error: 'Server error' }); });
const bad = (res, m, c = 400) => res.status(c).json({ error: m });
const isAdmin = async e => e === BOSS || (await q('select 1 from admins where email=$1', [e])).rowCount > 0;
const EM = /^[^@\s]+@[^@\s]+\.[^@\s]+$/, DT = /^\d{4}-\d{2}-\d{2}$/, TM = /^\d{2}:\d{2}$/;

app.use(async (req, res, next) => {
  try {
    const c = (req.headers.cookie || '').split(';').map(s => s.trim().split('=')).find(a => a[0] === 'sid');
    const email = c && ver(c[1]); req.user = null;
    if (email) { const r = await q('select email,name from users where email=$1', [email]); if (r.rowCount) req.user = { ...r.rows[0], admin: await isAdmin(email) }; }
    next();
  } catch (e) { next(e); }
});
const need = (req, res) => { if (!req.user || !req.user.admin) { bad(res, 'Only admins can do this.', 403); return false; } return true; };
const setCookie = (req, res, email) => res.setHeader('Set-Cookie', `sid=${mk(email)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=604800${req.secure ? '; Secure' : ''}`);

// Admin sets a password the first time (email must be ADMIN_EMAIL or added by an admin)
app.post('/api/register', w(async (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 80), email = String(req.body.email || '').trim().toLowerCase(), pw = String(req.body.password || '');
  if (!name || !EM.test(email) || pw.length < 8) return bad(res, 'Enter name, a valid email and a password of 8+ characters.');
  if (!(await isAdmin(email))) return bad(res, 'This email is not an approved admin. Ask an admin to add it first.', 403);
  if ((await q('select 1 from users where email=$1', [email])).rowCount) return bad(res, 'Password already set. Please sign in.');
  const salt = crypto.randomBytes(16).toString('hex');
  await q('insert into users(email,name,salt,hash) values($1,$2,$3,$4)', [email, name, salt, await scrypt(pw, salt)]);
  setCookie(req, res, email); res.json({ ok: true });
}));
app.post('/api/login', w(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase(), pw = String(req.body.password || '');
  const r = await q('select * from users where email=$1', [email]);
  if (!r.rowCount) return bad(res, 'Wrong email or password.', 401);
  const h = Buffer.from(await scrypt(pw, r.rows[0].salt)), s = Buffer.from(r.rows[0].hash);
  if (h.length !== s.length || !crypto.timingSafeEqual(h, s)) return bad(res, 'Wrong email or password.', 401);
  setCookie(req, res, email); res.json({ ok: true });
}));
app.post('/api/logout', (req, res) => { res.setHeader('Set-Cookie', 'sid=; HttpOnly; Path=/; Max-Age=0'); res.json({ ok: true }); });
app.get('/api/me', (req, res) => res.json({ user: req.user, rooms: ROOMS, now: now() }));

app.get('/api/bookings', w(async (req, res) => {
  const f = String(req.query.from || ''), t = String(req.query.to || '');
  if (!DT.test(f) || !DT.test(t)) return bad(res, 'Bad dates.');
  const r = await q(`select id,room,date,start_time as start,end_time as "end",title,by_name,notes from bookings where date>=$1 and date<=$2 order by date,start_time`, [f, t]);
  res.json(r.rows);
}));
function check(b) {
  const f = { room: b.room, date: b.date, start: b.start, end: b.end, title: String(b.title || '').trim().slice(0, 120), notes: String(b.notes || '').trim().slice(0, 300), by: String(b.by || '').trim().slice(0, 60) };
  if (!ROOMS.includes(f.room)) return 'Choose a valid room.';
  if (!DT.test(f.date) || !TM.test(f.start) || !TM.test(f.end)) return 'Enter a valid date and time.';
  if (!f.title) return 'Please enter a meeting title.';
  if (f.end <= f.start) return 'End time must be after start time.';
  const n = now();
  if (f.date < n.d) return 'Booking a past date is not allowed.';
  if (f.date === n.d && f.start <= n.t) return 'Booking a past time is not allowed.';
  return f;
}
const clash = async (f, id) => (await q('select 1 from bookings where room=$1 and date=$2 and start_time<$4 and end_time>$3 and id<>$5', [f.room, f.date, f.start, f.end, id || 0])).rowCount > 0;
app.post('/api/bookings', w(async (req, res) => {
  const f = check(req.body); if (typeof f === 'string') return bad(res, f);
  const by = f.by || (req.user && req.user.name); if (!by) return bad(res, 'Please enter your name.');
  if (await clash(f)) return bad(res, 'This slot is already booked. First come, first served.', 409);
  await q('insert into bookings(room,date,start_time,end_time,title,by_name,by_email,notes) values($1,$2,$3,$4,$5,$6,$7,$8)', [f.room, f.date, f.start, f.end, f.title, by, req.user ? req.user.email : '', f.notes]);
  res.json({ ok: true });
}));
app.put('/api/bookings/:id', w(async (req, res) => {
  if (!need(req, res)) return; const id = parseInt(req.params.id, 10), f = check(req.body); if (typeof f === 'string') return bad(res, f);
  if (await clash(f, id)) return bad(res, 'That room is already booked in this time slot.', 409);
  await q('update bookings set room=$1,date=$2,start_time=$3,end_time=$4,title=$5,notes=$6,by_name=coalesce(nullif($7,\'\'),by_name) where id=$8', [f.room, f.date, f.start, f.end, f.title, f.notes, f.by, id]);
  res.json({ ok: true });
}));
app.delete('/api/bookings/:id', w(async (req, res) => {
  if (!need(req, res)) return; await q('delete from bookings where id=$1', [parseInt(req.params.id, 10)]); res.json({ ok: true });
}));
app.get('/api/admins', w(async (req, res) => {
  if (!need(req, res)) return; const r = await q('select email from admins order by email');
  res.json({ owner: BOSS, admins: r.rows.map(x => x.email) });
}));
app.post('/api/admins', w(async (req, res) => {
  if (!need(req, res)) return; const e = String(req.body.email || '').trim().toLowerCase();
  if (!EM.test(e)) return bad(res, 'Enter a valid email address.');
  await q('insert into admins(email) values($1) on conflict do nothing', [e]); res.json({ ok: true });
}));
app.delete('/api/admins/:email', w(async (req, res) => {
  if (!need(req, res)) return; const e = req.params.email.toLowerCase();
  if (e === BOSS) return bad(res, 'The primary admin cannot be removed.');
  await q('delete from admins where email=$1', [e]); res.json({ ok: true });
}));

app.use(express.static(path.join(__dirname, 'public')));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

(async () => {
  await q(`create table if not exists users(email text primary key,name text not null,salt text not null,hash text not null);
  create table if not exists admins(email text primary key);
  create table if not exists bookings(id serial primary key,room text not null,date text not null,start_time text not null,end_time text not null,title text not null,by_name text,by_email text,created timestamptz default now());
  alter table bookings add column if not exists notes text;
  create index if not exists bk_date on bookings(date);`);
  app.listen(process.env.PORT || 3000, () => console.log('DLF scheduler running'));
})().catch(e => { console.error(e); process.exit(1); });
