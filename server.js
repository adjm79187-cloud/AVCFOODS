const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const root = __dirname;
const dataDir = path.join(root, 'data');
const dbFile = path.join(dataDir, 'avc-foods.json');
const sessions = new Map();

function hash(password, salt = crypto.randomBytes(16).toString('hex')) {
  return { salt, value: crypto.pbkdf2Sync(String(password), salt, 120000, 32, 'sha256').toString('hex') };
}
function checkPassword(password, user) {
  return hash(password, user.salt).value === user.passwordHash;
}
function initialDb() {
  return {
    users: [],
    products: [], orders: [], staff: [], settings: { company: 'AVC FOODS' }
  };
}
function loadDb() {
  if (!fs.existsSync(dbFile)) { fs.mkdirSync(dataDir, { recursive: true }); fs.writeFileSync(dbFile, JSON.stringify(initialDb(), null, 2)); }
  return JSON.parse(fs.readFileSync(dbFile, 'utf8'));
}
function saveDb(db) { fs.writeFileSync(dbFile, JSON.stringify(db, null, 2)); }
function id(prefix) { return `${prefix}-${Date.now().toString(36).toUpperCase()}${crypto.randomBytes(2).toString('hex').toUpperCase()}`; }
function json(res, status, body) { res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(body)); }
function parseCookies(req) { return Object.fromEntries((req.headers.cookie || '').split(';').filter(Boolean).map(x => { const p = x.trim().split('='); return [p.shift(), decodeURIComponent(p.join('='))]; })); }
function sessionUser(req, db) { const token = parseCookies(req).avc_session; const s = token && sessions.get(token); return s && db.users.find(u => u.id === s.userId); }
function requireRole(req, res, db, roles) { const user = sessionUser(req, db); if (!user) { json(res, 401, { error: 'Login required' }); return null; } if (roles && !roles.includes(user.role)) { json(res, 403, { error: 'Access denied' }); return null; } return user; }
function body(req) { return new Promise((resolve, reject) => { let raw = ''; req.on('data', c => { raw += c; if (raw.length > 4e6) req.destroy(); }); req.on('end', () => { try { resolve(raw ? JSON.parse(raw) : {}); } catch { reject(new Error('Invalid data')); } }); }); }
function safeUser(u) { return { id: u.id, name: u.name, email: u.email, phone: u.phone, role: u.role }; }
function dashboard(db) {
  const orders = db.orders;
  const completed = orders.filter(o => ['Delivered', 'Dispatched'].includes(o.status));
  const revenue = completed.reduce((sum, o) => sum + Number(o.total || 0), 0);
  const todayKey = new Date().toISOString().slice(0, 10);
  const today = orders.filter(o => String(o.createdAt || '').slice(0, 10) === todayKey);
  const lowStock = db.products.filter(p => Number(p.stock || 0) <= Number(p.lowStockAt || 10));
  const salesDays = Array.from({ length: 7 }, (_, index) => {
    const d = new Date(); d.setDate(d.getDate() - (6 - index)); const key = d.toISOString().slice(0, 10);
    return { label: d.toLocaleDateString('en-IN', { weekday: 'short' }), value: orders.filter(o => String(o.createdAt || '').slice(0, 10) === key && !['Cancelled', 'Rejected'].includes(o.status)).reduce((s, o) => s + Number(o.total || 0), 0) };
  });
  const sold = {};
  orders.filter(o => !['Cancelled', 'Rejected'].includes(o.status)).forEach(o => (o.items || []).forEach(i => { sold[i.name] = (sold[i.name] || 0) + Number(i.qty || 1); }));
  return {
    metrics: { totalSales: revenue, todaySales: today.filter(o => !['Cancelled', 'Rejected'].includes(o.status)).reduce((s, o) => s + Number(o.total || 0), 0), totalOrders: orders.length, pendingOrders: orders.filter(o => ['Received', 'Processing', 'Packed'].includes(o.status)).length, deliveredOrders: orders.filter(o => o.status === 'Delivered').length, cancelledOrders: orders.filter(o => ['Cancelled', 'Rejected'].includes(o.status)).length, customers: new Set(orders.map(o => o.customer?.phone || o.customer?.email).filter(Boolean)).size, lowStock: lowStock.length, cod: orders.filter(o => o.payment === 'Cash on Delivery').reduce((s, o) => s + Number(o.total || 0), 0), online: orders.filter(o => o.payment !== 'Cash on Delivery').reduce((s, o) => s + Number(o.total || 0), 0) },
    salesDays, bestSellers: Object.entries(sold).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([name, quantity]) => ({ name, quantity })), lowStockProducts: lowStock, recentOrders: orders.slice().sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt))).slice(0, 7)
  };
}
const mime = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.svg': 'image/svg+xml', '.webp': 'image/webp' };

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost'); const method = req.method; const db = loadDb();
  try {
    if (url.pathname === '/api/login' && method === 'POST') {
      const input = await body(req); const user = db.users.find(u => (u.email === input.login || u.phone === input.login || u.id === input.login) && u.role === input.role);
      if (!user || !checkPassword(input.password, user)) return json(res, 401, { error: 'Login details galat hain.' });
      const token = crypto.randomBytes(32).toString('hex'); sessions.set(token, { userId: user.id, expires: Date.now() + 8 * 60 * 60 * 1000 });
      res.setHeader('Set-Cookie', `avc_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800`); return json(res, 200, { user: safeUser(user) });
    }
    if (url.pathname === '/api/setup-owner' && method === 'POST') {
      if (db.users.length) return json(res, 409, { error: 'Owner account pehle se set hai.' });
      const input = await body(req);
      if (!input.name || !input.email || !input.phone || String(input.password || '').length < 8) return json(res, 400, { error: 'Name, mobile, email aur kam se kam 8 character ka password zaruri hai.' });
      const password = hash(input.password);
      const user = { id: id('OWN'), name: input.name.trim(), email: input.email.trim().toLowerCase(), phone: input.phone.trim(), role: 'owner', salt: password.salt, passwordHash: password.value, createdAt: new Date().toISOString() };
      db.users.push(user); saveDb(db);
      const token = crypto.randomBytes(32).toString('hex'); sessions.set(token, { userId: user.id, expires: Date.now() + 8 * 60 * 60 * 1000 });
      res.setHeader('Set-Cookie', `avc_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800`); return json(res, 201, { user: safeUser(user) });
    }
    if (url.pathname === '/api/logout' && method === 'POST') { const token = parseCookies(req).avc_session; if (token) sessions.delete(token); res.setHeader('Set-Cookie', 'avc_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'); return json(res, 200, { ok: true }); }
    if (url.pathname === '/api/session' && method === 'GET') { const user = sessionUser(req, db); return user ? json(res, 200, { user: safeUser(user) }) : json(res, 401, { error: 'No session' }); }
    if (url.pathname === '/api/public/orders' && method === 'POST') {
      const input = await body(req);
      if (!input.customer?.name || !input.customer?.phone || !Array.isArray(input.items) || !input.items.length) return json(res, 400, { error: 'Order details incomplete' });
      const order = { id: input.id || id('AVC'), customer: input.customer, items: input.items, total: Number(input.total || 0), payment: input.payment || 'Cash on Delivery', status: 'Received', createdAt: new Date().toISOString() };
      db.orders.push(order); saveDb(db); return json(res, 201, { id: order.id });
    }
    if (url.pathname === '/api/dashboard' && method === 'GET') { if (!requireRole(req, res, db, ['owner', 'manager', 'staff'])) return; return json(res, 200, dashboard(db)); }
    if (url.pathname === '/api/products') {
      if (method === 'GET') { if (!requireRole(req, res, db, ['owner', 'manager', 'staff'])) return; return json(res, 200, db.products); }
      if (!requireRole(req, res, db, ['owner', 'manager'])) return;
      if (method === 'POST') { const p = await body(req); const product = { id: id('PRD'), name: p.name || 'Untitled Product', category: p.category || 'Other', price: Number(p.price || 0), stock: Number(p.stock || 0), lowStockAt: Number(p.lowStockAt || 10), image: p.image || '', createdAt: new Date().toISOString() }; db.products.push(product); saveDb(db); return json(res, 201, product); }
    }
    const productMatch = url.pathname.match(/^\/api\/products\/([^/]+)$/);
    if (productMatch && ['PUT', 'DELETE'].includes(method)) { if (!requireRole(req, res, db, ['owner', 'manager'])) return; const index = db.products.findIndex(p => p.id === productMatch[1]); if (index < 0) return json(res, 404, { error: 'Product not found' }); if (method === 'DELETE') { db.products.splice(index, 1); saveDb(db); return json(res, 200, { ok: true }); } const input = await body(req); db.products[index] = { ...db.products[index], ...input, price: Number(input.price), stock: Number(input.stock), lowStockAt: Number(input.lowStockAt || 10) }; saveDb(db); return json(res, 200, db.products[index]); }
    if (url.pathname === '/api/orders' && method === 'GET') { if (!requireRole(req, res, db, ['owner', 'manager', 'staff'])) return; return json(res, 200, db.orders.slice().sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)))); }
    const orderMatch = url.pathname.match(/^\/api\/orders\/([^/]+)$/);
    if (orderMatch && method === 'PUT') { if (!requireRole(req, res, db, ['owner', 'manager', 'staff'])) return; const index = db.orders.findIndex(o => o.id === orderMatch[1]); if (index < 0) return json(res, 404, { error: 'Order not found' }); const input = await body(req); const allowed = ['Received', 'Processing', 'Packed', 'Dispatched', 'Delivered', 'Rejected', 'Cancelled']; if (input.status && allowed.includes(input.status)) db.orders[index].status = input.status; db.orders[index].updatedAt = new Date().toISOString(); saveDb(db); return json(res, 200, db.orders[index]); }
    if (url.pathname === '/api/customers' && method === 'GET') { if (!requireRole(req, res, db, ['owner', 'manager'])) return; const customers = Object.values(db.orders.reduce((map, o) => { const key = o.customer?.phone || o.customer?.email || o.id; if (!map[key]) map[key] = { ...o.customer, orders: 0, spent: 0 }; map[key].orders++; map[key].spent += Number(o.total || 0); return map; }, {})); return json(res, 200, customers); }
    if (url.pathname === '/api/staff') {
      if (method === 'GET') { if (!requireRole(req, res, db, ['owner', 'manager'])) return; return json(res, 200, db.staff); }
      if (!requireRole(req, res, db, ['owner'])) return;
      if (method === 'POST') { const input = await body(req); const tempPassword = input.password || crypto.randomBytes(4).toString('hex'); const pw = hash(tempPassword); const employee = { id: id('EMP'), name: input.name || '', phone: input.phone || '', email: input.email || '', role: input.role === 'manager' ? 'manager' : 'staff', salary: Number(input.salary || 0), attendance: [], createdAt: new Date().toISOString() }; db.staff.push(employee); db.users.push({ ...employee, salt: pw.salt, passwordHash: pw.value }); saveDb(db); return json(res, 201, { employee, temporaryPassword: tempPassword }); }
    }
    const staffMatch = url.pathname.match(/^\/api\/staff\/([^/]+)$/);
    if (staffMatch && method === 'DELETE') { if (!requireRole(req, res, db, ['owner'])) return; db.staff = db.staff.filter(s => s.id !== staffMatch[1]); db.users = db.users.filter(u => u.id !== staffMatch[1]); saveDb(db); return json(res, 200, { ok: true }); }
    if (url.pathname === '/api/reports.csv' && method === 'GET') { if (!requireRole(req, res, db, ['owner', 'manager'])) return; const lines = ['Order ID,Date,Customer,Status,Payment,Total', ...db.orders.map(o => [o.id, o.createdAt, o.customer?.name || '', o.status, o.payment, o.total].map(v => `"${String(v || '').replaceAll('"', '""')}"`).join(','))]; res.writeHead(200, { 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': 'attachment; filename="avc-orders-report.csv"' }); return res.end(lines.join('\n')); }
    if (url.pathname === '/api/backup' && method === 'GET') { if (!requireRole(req, res, db, ['owner'])) return; const clean = { ...db, users: db.users.map(safeUser), exportedAt: new Date().toISOString() }; res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Disposition': 'attachment; filename="avc-backup.json"' }); return res.end(JSON.stringify(clean, null, 2)); }

    let target = url.pathname === '/' ? '/index.html' : url.pathname; target = path.normalize(target).replace(/^([.][.][\\/])+/, ''); const file = path.join(root, target);
    if (!file.startsWith(root) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) return json(res, 404, { error: 'Not found' });
    res.writeHead(200, { 'Content-Type': mime[path.extname(file).toLowerCase()] || 'application/octet-stream' }); fs.createReadStream(file).pipe(res);
  } catch (error) { console.error(error); json(res, 500, { error: 'Server error' }); }
});
server.listen(process.env.PORT || 4173, () => console.log('AVC FOODS server running at http://localhost:4173'));
