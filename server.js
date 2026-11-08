'use strict';
const express = require('express'), crypto = require('crypto'), fs = require('fs'), path = require('path');
const PROD = process.env.NODE_ENV === 'production';
const SECRET = process.env.SESSION_SECRET || (PROD ? '' : 'dev-secret-change-me');
const SETUP_CODE = process.env.SETUP_CODE || (PROD ? '' : 'dev-setup');
const COLS = ['users','classes','affect','matieres','salles','eleves','notes','edt','paiements','devoirs','depots','msgs','absences','tarifs','annonces','notifs','audit'];
const ROLES = ['admin','enseignant','parent','eleve','comptable'];
const FRONT = ['notifs','audit','annonces'];                        // nouvelles lignes ajoutées en tête
const keyOf = (c, r) => c === 'depots' ? r.hid + '|' + r.sid : r.id;

/* ---------- Stockage (PostgreSQL en production, fichier JSON en local) ---------- */
function fileStore(file) {
  let d = fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, 'utf8')) : { state: null, version: 0, files: {} };
  const w = () => fs.writeFileSync(file, JSON.stringify(d));
  return { async init() {}, async load() { return { state: d.state, version: d.version }; },
    async save(s, v) { d.state = s; d.version = v; w(); },
    async putFile(f) { d.files[f.id] = f; w(); }, async getFile(id) { return d.files[id] || null; } };
}
function pgStore(pool) {
  return {
    async init() {
      try { await pool.query('select 1 from app_state limit 1'); await pool.query('select 1 from files limit 1'); }
      catch (e) {
        await pool.query('create table if not exists app_state(id int primary key, data jsonb not null, version bigint not null)');
        await pool.query('create table if not exists files(id text primary key, name text not null, data text not null, owner text)');
      }
    },
    async load() { const r = await pool.query('select data, version from app_state where id=1'); return r.rows[0] ? { state: r.rows[0].data, version: +r.rows[0].version } : { state: null, version: 0 }; },
    async save(s, v) { await pool.query('insert into app_state(id,data,version) values(1,$1,$2) on conflict (id) do update set data=excluded.data, version=excluded.version', [JSON.stringify(s), v]); },
    async putFile(f) { await pool.query('insert into files(id,name,data,owner) values($1,$2,$3,$4)', [f.id, f.name, f.data, f.owner]); },
    async getFile(id) { const r = await pool.query('select * from files where id=$1', [id]); return r.rows[0] || null; }
  };
}

/* ---------- Mots de passe ---------- */
const scrypt = (pw, salt) => new Promise((res, rej) => crypto.scrypt(pw, salt, 32, (e, k) => e ? rej(e) : res(k.toString('hex'))));
const mkPw = async pw => { const salt = crypto.randomBytes(16).toString('hex'); return { salt, hash: await scrypt(pw, salt) }; };
const chkPw = async (pw, u) => { const a = Buffer.from(await scrypt(pw, u.salt), 'hex'), b = Buffer.from(u.hash, 'hex'); return a.length === b.length && crypto.timingSafeEqual(a, b); };
const RULES = [[p => p.length >= 8, 'au moins 8 caractères'], [p => /[A-Z]/.test(p), 'une majuscule'], [p => /[a-z]/.test(p), 'une minuscule'], [p => /\d/.test(p), 'un chiffre'], [p => !/\s/.test(p), 'aucun espace']];
const pwErr = p => { const r = RULES.find(x => !x[0](String(p || ''))); return r ? 'Le mot de passe doit avoir : ' + r[1] + '.' : ''; };
const pick = (s, n) => [...crypto.randomBytes(n)].map(b => s[b % s.length]).join('');
const genPw = () => pick('ABCDEFGHJKLMNPQRSTUVWXYZ', 1) + pick('abcdefghijkmnpqrstuvwxyz', 2) + '-' + pick('23456789', 3) + '-' + pick('abcdefghijkmnpqrstuvwxyz', 3);
const uid = p => p + crypto.randomBytes(5).toString('hex');
const sha = s => crypto.createHash('sha256').update(String(s)).digest();

function emptyState() {
  const s = {}; COLS.forEach(c => s[c] = []);
  s.matieres = [{ id: 'Français', coef: 3 }, { id: 'Mathématiques', coef: 3 }, { id: 'Éveil scientifique', coef: 2 }];
  s.tarifs = [['CP', 1300], ['CE1', 1300], ['CE2', 1350], ['CM1', 1400], ['CM2', 1400]].map(([n, c], k) => ({ id: 'tf' + k, annee: '2026-2027', niveau: n, inscription: 200, scolarite: c, tranches: 3 }));
  return s;
}

/* ---------- Visibilité des données selon le rôle ---------- */
const tcl = (S, u) => [...new Set([...S.classes.filter(c => c.titulaire === u.id).map(c => c.id), ...S.affect.filter(a => a.prof === u.id).map(a => a.classe)])];
const pubU = x => ({ id: x.id, nom: x.nom, role: x.role, enfants: x.enfants, sid: x.sid, actif: x.actif });
const admU = x => ({ ...pubU(x), login: x.login, email: x.email, tel: x.tel, must: !!x.must });
const meOf = x => ({ ...admU(x) });
function view(S, u) {
  const r = u.role, o = {}; COLS.forEach(c => o[c] = []);
  o.matieres = S.matieres; o.classes = S.classes; o.salles = S.salles; o.affect = S.affect;
  o.annonces = S.annonces.filter(a => r === 'admin' || a.cible === 'tous' || a.cible === r);
  o.notifs = S.notifs.filter(n => n.to === u.id);
  o.msgs = S.msgs.filter(m => m.de === u.id || m.a === u.id);
  const users = new Set([u.id]); S.users.filter(x => x.role === 'admin').forEach(x => users.add(x.id));
  o.msgs.forEach(m => { users.add(m.de); users.add(m.a); });
  if (r === 'admin') {
    COLS.forEach(c => { if (!['users', 'msgs', 'notifs', 'annonces'].includes(c)) o[c] = S[c]; });
    o.users = S.users.map(admU);
  } else if (r === 'comptable') {
    o.eleves = S.eleves; o.paiements = S.paiements; o.tarifs = S.tarifs; S.users.filter(x => x.role === 'parent').forEach(x => users.add(x.id));
  } else {
    o.edt = S.edt; o.tarifs = S.tarifs;
    let kidIds;
    if (r === 'enseignant') {
      const my = tcl(S, u); o.eleves = S.eleves.filter(s => my.includes(s.classe)); kidIds = new Set(o.eleves.map(s => s.id));
      o.notes = S.notes.filter(n => n.prof === u.id); o.devoirs = S.devoirs.filter(d => d.prof === u.id);
      const dv = new Set(o.devoirs.map(d => d.id)); o.depots = S.depots.filter(d => dv.has(d.hid)); o.absences = S.absences.filter(a => a.prof === u.id);
    } else {
      kidIds = new Set(r === 'parent' ? (u.enfants || []) : [u.sid]); o.eleves = S.eleves.filter(s => kidIds.has(s.id));
      const cl = new Set(o.eleves.map(s => s.classe));
      o.notes = S.notes.filter(n => kidIds.has(n.sid)); o.devoirs = S.devoirs.filter(d => cl.has(d.classe));
      o.depots = S.depots.filter(d => kidIds.has(d.sid)); o.absences = S.absences.filter(a => kidIds.has(a.sid));
      if (r === 'parent') o.paiements = S.paiements.filter(p => kidIds.has(p.sid));
      S.users.filter(x => x.role === 'enseignant' && tcl(S, x).some(c => cl.has(c))).forEach(x => users.add(x.id));
    }
    S.users.forEach(x => { if ((x.role === 'parent' && (x.enfants || []).some(i => kidIds.has(i))) || (x.role === 'eleve' && kidIds.has(x.sid))) users.add(x.id); });
  }
  if (r !== 'admin') o.users = S.users.filter(x => users.has(x.id)).map(x => x.id === u.id ? meOf(x) : pubU(x));
  return o;
}

/* ---------- Droits d'écriture (qui peut modifier quoi) ---------- */
const same = (a, b, skip) => { const x = { ...a }, y = { ...b }; skip.forEach(k => { delete x[k]; delete y[k]; }); return JSON.stringify(x) === JSON.stringify(y); };
function allowed(S, u, c, k, row, old, ctx) {
  const me = u.id, r = u.role, adm = r === 'admin';
  switch (c) {
    case 'classes': case 'affect': case 'matieres': case 'salles': case 'eleves': case 'edt': return adm;
    case 'tarifs': case 'paiements': return adm || r === 'comptable';
    case 'annonces': return adm && k === 'set' && !old;
    case 'users': return adm && !!old && (k === 'set' ? (row.id !== me || row.actif !== false) : old.id !== me);
    case 'notes': {
      if (r !== 'enseignant') return false; const t = k === 'del' ? old : row; if (!t || (old && old.prof !== me) || t.prof !== me) return false;
      const s = S.eleves.find(x => x.id === t.sid); return !!s && tcl(S, u).includes(s.classe);
    }
    case 'devoirs': {
      if (r === 'enseignant') { if (k === 'del') { if (old && old.prof === me) { ctx.gone[old.id] = true; return true; } return false; } return row.prof === me && (!old || old.prof === me) && tcl(S, u).includes(row.classe); }
      if (r === 'parent' && k === 'set' && old) { const add = (row.vus || []).filter(x => !(old.vus || []).includes(x)); return same(row, old, ['vus']) && add.every(x => { const [pu, sid] = x.split(':'); return pu === me && (u.enfants || []).includes(sid); }); }
      return false;
    }
    case 'depots': {
      const dv = S.devoirs.find(d => d.id === (row ? row.hid : old.hid));
      if (r === 'eleve') { if (k !== 'set' || row.sid !== u.sid || !dv) return false; const s = S.eleves.find(x => x.id === u.sid); return !!s && s.classe === dv.classe && (!old || old.note == null) && row.note == null; }
      if (r === 'enseignant') { if (k === 'del') return !!old && ((dv && dv.prof === me) || ctx.gone[old.hid]); return !!old && !!dv && dv.prof === me && same(row, old, ['note', 'comm']); }
      return false;
    }
    case 'absences': {
      if (r === 'enseignant') { if (k === 'del') return !!old && old.prof === me; return row.prof === me && (!old || old.prof === me); }
      if (!old || k !== 'set') return adm && k === 'del';
      if (r === 'parent') return (u.enfants || []).includes(old.sid) && same(row, old, ['statut', 'motif', 'comm', 'just', 'pdf']) && row.statut === 'En attente';
      return adm && same(row, old, ['statut']) && ['Justifiée', 'Refusée'].includes(row.statut);
    }
    case 'msgs': {
      if (k === 'del') return !!old && old.de === me && !!old.brouillon;
      if (old && old.a === me && old.de !== me) return same(row, old, ['masque']);
      return row.de === me && (!old || (old.de === me && old.brouillon)) && S.users.some(x => x.id === row.a);
    }
    case 'notifs': return old ? old.to === me : (k === 'set' && S.users.some(x => x.id === row.to));
    case 'audit': return k === 'set' && !old;
  }
  return false;
}

/* ---------- Application ---------- */
function createApp({ store }) {
  const app = express(); app.set('trust proxy', 1); app.disable('x-powered-by');
  let S = null, V = 0, chain = Promise.resolve();
  const lock = fn => { const p = chain.then(fn, fn); chain = p.catch(() => {}); return p; };
  const ready = (async () => { await store.init(); const l = await store.load(); S = l.state || emptyState(); V = l.version; })();
  const persist = async () => { V++; await store.save(S, V); };
  const sign = s => crypto.createHmac('sha256', SECRET).update(s).digest('base64url');
  const cookie = u => { const b = Buffer.from(JSON.stringify({ u: u.id, tv: u.tv || 0, exp: Date.now() + 12 * 3600e3 })).toString('base64url'); return `sid=${b}.${sign(b)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=43200${PROD ? '; Secure' : ''}`; };
  const userOf = req => {
    const c = (req.headers.cookie || '').split(';').map(x => x.trim()).find(x => x.startsWith('sid=')); if (!c) return null;
    const [b, sg] = c.slice(4).split('.'); if (!b || !sg || sg.length !== sign(b).length || !crypto.timingSafeEqual(Buffer.from(sg), Buffer.from(sign(b)))) return null;
    let p; try { p = JSON.parse(Buffer.from(b, 'base64url').toString()); } catch (e) { return null; }
    const u = S.users.find(x => x.id === p.u); return u && u.actif && (u.tv || 0) === p.tv && p.exp > Date.now() ? u : null;
  };
  app.use((req, res, next) => {
    res.set({ 'X-Frame-Options': 'DENY', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
      'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'" });
    if (PROD) res.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    next();
  });
  app.use('/api', express.json({ limit: '2mb' }));
  app.use('/api', (req, res, next) => { if (req.method === 'POST') { const o = req.headers.origin; if (o && new URL(o).host !== req.headers.host) return res.status(403).json({ error: 'Origine refusée.' }); } res.set('Cache-Control', 'no-store'); next(); });
  app.use('/api', async (req, res, next) => { await ready; req.user = userOf(req); next(); });
  const need = (req, res, next) => req.user ? next() : res.status(401).json({ error: 'Veuillez vous connecter.' });
  const admin = (req, res, next) => req.user.role === 'admin' ? next() : res.status(403).json({ error: 'Réservé à l’administration.' });
  const wrap = fn => (req, res) => lock(() => fn(req, res)).catch(e => { console.error(e); res.status(500).json({ error: 'Erreur du serveur.' }); });
  const audit = (u, a, d) => S.audit.unshift({ id: uid('L'), t: new Date().toLocaleString('fr-FR', { timeZone: 'Africa/Tunis' }), u: u.nom, a, d: d || '' });

  const fails = new Map();
  const tooMany = k => { const f = fails.get(k); return f && f.until > Date.now() ? Math.ceil((f.until - Date.now()) / 60000) : 0; };
  const fail = k => { const f = fails.get(k) || { n: 0, until: 0 }; if (f.until && f.until <= Date.now()) { f.n = 0; f.until = 0; } f.n++; if (f.n >= 5) { f.until = Date.now() + 5 * 60000; f.n = 0; } fails.set(k, f); };

  app.get('/api/session', (req, res) => res.json({ setup: S.users.length === 0, me: req.user ? meOf(req.user) : null }));

  app.post('/api/setup', wrap(async (req, res) => {
    if (S.users.length) return res.status(409).json({ error: 'L’application est déjà configurée.' });
    const { code, nom, login, password } = req.body || {}, ip = 'setup|' + req.ip;
    if (tooMany(ip)) return res.status(429).json({ error: 'Trop d’essais. Patientez quelques minutes.' });
    if (!SETUP_CODE || !crypto.timingSafeEqual(sha(code), sha(SETUP_CODE))) { fail(ip); return res.status(403).json({ error: 'Code d’installation incorrect.' }); }
    if (!/^\p{L}[\p{L}'’. -]{2,59}$/u.test(String(nom || '').trim())) return res.status(400).json({ error: 'Nom invalide (3 à 60 lettres).' });
    if (!/^[a-z0-9._-]{3,20}$/.test(String(login || ''))) return res.status(400).json({ error: 'Identifiant : 3 à 20 caractères (a-z, 0-9, point, tiret).' });
    const pe = pwErr(password); if (pe) return res.status(400).json({ error: pe });
    const u = { id: 'u1', nom: String(nom).trim(), role: 'admin', login, email: '', tel: '', ...(await mkPw(password)), must: false, actif: true, tv: 0 };
    S.users.push(u); audit(u, 'Installation', 'Compte administrateur créé'); await persist();
    res.set('Set-Cookie', cookie(u)).json({ ok: true });
  }));

  app.post('/api/login', wrap(async (req, res) => {
    const l = String((req.body || {}).login || '').trim().toLowerCase(), pw = String((req.body || {}).password || '').trim(), k1 = 'l|' + l, k2 = 'i|' + req.ip;
    const w = tooMany(k1) || tooMany(k2); if (w) return res.status(429).json({ error: 'Trop d’essais. Patientez ' + w + ' minute(s) puis réessayez.' });
    const u = S.users.find(x => x.login === l);
    const ok = u ? await chkPw(pw, u) : (await scrypt(pw, 'x'.repeat(32)), false);
    if (!ok) { fail(k1); fail(k2); return res.status(401).json({ error: 'Identifiant ou mot de passe incorrect. Vérifiez que vous écrivez l’identifiant de la fiche (pas votre nom) et que les majuscules du mot de passe sont respectées.' }); }
    if (!u.actif) return res.status(403).json({ error: 'Ce compte est désactivé. Contactez l’administration de l’école.' });
    fails.delete(k1); audit(u, 'Connexion'); await persist();
    res.set('Set-Cookie', cookie(u)).json({ ok: true });
  }));

  app.post('/api/logout', (req, res) => res.set('Set-Cookie', 'sid=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0').json({ ok: true }));

  app.post('/api/password', need, wrap(async (req, res) => {
    const { old, password } = req.body || {}, u = req.user;
    if (!(await chkPw(String(old || '').trim(), u))) return res.status(400).json({ error: 'Le mot de passe actuel n’est pas correct.' });
    const pe = pwErr(password); if (pe) return res.status(400).json({ error: pe });
    if (password === String(old).trim()) return res.status(400).json({ error: 'Le nouveau mot de passe doit être différent de l’ancien.' });
    if (String(password).toLowerCase() === u.login) return res.status(400).json({ error: 'Le mot de passe ne doit pas être votre identifiant.' });
    Object.assign(u, await mkPw(password), { must: false, tv: (u.tv || 0) + 1 }); audit(u, 'Mot de passe changé'); await persist();
    res.set('Set-Cookie', cookie(u)).json({ ok: true });
  }));

  app.get('/api/state', need, (req, res) => res.json({ version: V, me: meOf(req.user), state: view(S, req.user) }));

  app.post('/api/ops', need, wrap(async (req, res) => {
    const ops = (req.body || {}).ops; if (!Array.isArray(ops) || ops.length > 600) return res.status(400).json({ error: 'Requête invalide.' });
    const T = JSON.parse(JSON.stringify(S)), ctx = { gone: {} }, u = T.users.find(x => x.id === req.user.id);
    for (const op of ops) {
      const { c, k, row } = op || {};
      if (!COLS.includes(c) || !['set', 'del'].includes(k) || !row || typeof row !== 'object' || Array.isArray(row)) return res.status(400).json({ error: 'Opération invalide.' });
      const key = keyOf(c, row); if (!key || key.includes('undefined')) return res.status(400).json({ error: 'Identifiant manquant.' });
      const idx = T[c].findIndex(x => keyOf(c, x) === key), old = idx >= 0 ? T[c][idx] : null;
      if (k === 'del' && !old) continue;
      if (!allowed(T, u, c, k, row, old, ctx)) return res.status(403).json({ error: 'Action non autorisée pour votre profil (' + c + ').' });
      if (k === 'del') { T[c].splice(idx, 1); continue; }
      let nr = row;
      if (c === 'users') { const f = ['nom', 'email', 'tel', 'enfants', 'sid', 'actif']; nr = { ...old }; f.forEach(x => { if (x in row) nr[x] = row[x]; }); }
      if (c === 'audit') nr = { id: row.id, t: new Date().toLocaleString('fr-FR', { timeZone: 'Africa/Tunis' }), u: u.nom, a: String(row.a || '').slice(0, 120), d: String(row.d || '').slice(0, 300) };
      if (idx >= 0) T[c][idx] = nr; else if (FRONT.includes(c)) T[c].unshift(nr); else T[c].push(nr);
    }
    if (!T.users.some(x => x.role === 'admin' && x.actif)) return res.status(403).json({ error: 'Il doit rester un administrateur actif.' });
    S = T; await persist(); res.json({ version: V });
  }));

  const loginOf = nom => { const b = nom.normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase().replace(/^(m|mme|mlle)\.?\s+/, '').replace(/[^a-z0-9]+/g, '.').replace(/^\.|\.$/g, '').slice(0, 17) || 'user'; let l = b, i = 1; while (S.users.some(u => u.login === l)) l = b + (++i); return l; };
  app.post('/api/admin/account', need, admin, wrap(async (req, res) => {
    const { role, nom, email, tel, enfants, sid } = req.body || {}, n = String(nom || '').trim(), em = String(email || '').trim().toLowerCase(), tl = String(tel || '').replace(/[\s.-]/g, '');
    if (!ROLES.includes(role)) return res.status(400).json({ error: 'Type de compte invalide.' });
    if (role !== 'eleve' && !/^\p{L}[\p{L}'’. -]{2,59}$/u.test(n)) return res.status(400).json({ error: 'Le nom n’est pas correct : 3 à 60 lettres, sans chiffres.' });
    if (!/^[^\s@]+@[^\s@]+\.[a-z]{2,}$/.test(em)) return res.status(400).json({ error: 'L’adresse e-mail n’est pas correcte.' });
    if (tl && !/^(\+216)?\d{8}$/.test(tl)) return res.status(400).json({ error: 'Le téléphone doit avoir 8 chiffres.' });
    if (S.users.some(x => x.email === em)) return res.status(400).json({ error: 'Cette adresse e-mail est déjà utilisée par un autre compte.' });
    const u = { id: uid('u'), nom: n, role, login: '', email: em, tel: tl, must: true, actif: true, tv: 0 };
    if (role === 'parent') { const en = [...new Set(Array.isArray(enfants) ? enfants : [])].filter(i => S.eleves.some(s => s.id === i)); if (!en.length) return res.status(400).json({ error: 'Choisissez au moins un enfant.' }); u.enfants = en; }
    if (role === 'eleve') { const s = S.eleves.find(x => x.id === sid); if (!s) return res.status(400).json({ error: 'Élève introuvable.' }); if (S.users.some(x => x.role === 'eleve' && x.sid === sid)) return res.status(400).json({ error: 'Cet élève a déjà un compte.' }); u.sid = sid; u.nom = s.prenom + ' ' + s.nom; }
    u.login = loginOf(u.nom);
    const pw = genPw(); Object.assign(u, await mkPw(pw)); S.users.push(u); audit(req.user, 'Compte créé', u.nom + ' (' + role + ')'); await persist();
    res.json({ user: admU(u), pw });
  }));
  app.post('/api/admin/reset', need, admin, wrap(async (req, res) => {
    const u = S.users.find(x => x.id === (req.body || {}).id); if (!u) return res.status(404).json({ error: 'Compte introuvable.' });
    if (u.id === req.user.id) return res.status(400).json({ error: 'Pour votre propre mot de passe, utilisez « Mon compte ».' });
    const pw = genPw(); Object.assign(u, await mkPw(pw), { must: true, tv: (u.tv || 0) + 1 }); fails.delete('l|' + u.login); audit(req.user, 'Mot de passe réinitialisé', u.nom); await persist();
    res.json({ login: u.login, nom: u.nom, role: u.role, pw });
  }));

  app.post('/api/file', need, wrap(async (req, res) => {
    const { name, data } = req.body || {}; const m = /^data:[^;]*;base64,(.+)$/.exec(String(data || ''));
    if (!m) return res.status(400).json({ error: 'Fichier invalide.' });
    const buf = Buffer.from(m[1], 'base64'); if (buf.length < 100 || buf.length > 800 * 1024) return res.status(400).json({ error: 'Taille refusée (maximum 800 Ko).' });
    if (buf.slice(0, 5).toString() !== '%PDF-') return res.status(400).json({ error: 'Ce fichier n’est pas un PDF valide.' });
    const id = uid('F') + crypto.randomBytes(6).toString('hex'); await store.putFile({ id, name: String(name || 'document.pdf').slice(0, 80), data: m[1], owner: req.user.id });
    res.json({ fid: id, name: String(name || 'document.pdf').slice(0, 80) });
  }));
  app.get('/api/file/:id', need, async (req, res) => {
    const f = await store.getFile(req.params.id); if (!f) return res.status(404).json({ error: 'Fichier introuvable.' });
    const v = view(S, req.user), ref = [...v.depots, ...v.devoirs, ...v.absences].some(r => [r.pdf, r.corrigePdf].some(p => p && p.fid === f.id));
    if (!(req.user.role === 'admin' || f.owner === req.user.id || ref)) return res.status(403).json({ error: 'Accès refusé.' });
    res.set({ 'Content-Type': 'application/pdf', 'Content-Disposition': 'attachment; filename="' + f.name.replace(/[^\w.\- ]/g, '_') + '"' }).send(Buffer.from(f.data, 'base64'));
  });

  app.use('/api', (req, res) => res.status(404).json({ error: 'Introuvable.' }));
  app.use(express.static(path.join(__dirname, 'public'), { maxAge: 0, index: 'index.html' }));
  app.use((err, req, res, next) => { if (err && err.type === 'entity.too.large') return res.status(413).json({ error: 'Données trop volumineuses.' }); if (err instanceof SyntaxError) return res.status(400).json({ error: 'Requête invalide.' }); console.error(err); res.status(500).json({ error: 'Erreur du serveur.' }); });
  app.ready = ready; return app;
}

module.exports = { createApp, fileStore, pgStore, allowed, view };
if (require.main === module) {
  let store;
  if (process.env.DATABASE_URL) { const { Pool } = require('pg'); const local = /localhost|127\.0\.0\.1/.test(process.env.DATABASE_URL); store = pgStore(new Pool({ connectionString: process.env.DATABASE_URL, ssl: local ? false : { rejectUnauthorized: false }, max: 5 })); }
  else if (PROD) { console.error('DATABASE_URL, SESSION_SECRET et SETUP_CODE sont obligatoires en production.'); process.exit(1); }
  else store = fileStore(path.join(__dirname, 'data.local.json'));
  if (PROD && (!SECRET || !SETUP_CODE)) { console.error('SESSION_SECRET et SETUP_CODE sont obligatoires en production.'); process.exit(1); }
  const app = createApp({ store }), port = process.env.PORT || 3000;
  app.ready.then(() => app.listen(port, () => console.log('Serveur prêt sur le port ' + port)));
}
