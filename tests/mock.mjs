import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

const ROOT = new URL('..', import.meta.url).pathname;
const TOKEN = 'github_pat_TESTKEY';
const blobs = new Map();   // sha -> base64
const trees = new Map();   // sha -> Map(path -> blobSha)
const commits = new Map(); // sha -> treeSha
let head = null;           // commit sha
export const stats = { calls: 0 };

const sha = (s) => crypto.createHash('sha1').update(s + Math.random()).digest('hex');
const addBlob = (b64) => { const s = crypto.createHash('sha1').update(b64).digest('hex'); blobs.set(s, b64); return s; };
const addTree = (m) => { const s = sha('t'); trees.set(s, m); return s; };
const addCommit = (t) => { const s = sha('c'); commits.set(s, t); return s; };
const curTree = () => (head ? trees.get(commits.get(head)) : null);

function send(res, code, obj, headers = {}) {
  res.writeHead(code, { 'Content-Type': 'application/json', ...headers });
  res.end(obj === undefined ? '' : JSON.stringify(obj));
}

const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, 'http://x');
  if (!u.pathname.startsWith('/api/')) {
    const f = path.join(ROOT, u.pathname === '/' ? 'index.html' : u.pathname);
    if (!fs.existsSync(f)) return send(res, 404, { message: 'nf' });
    const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css' };
    res.writeHead(200, { 'Content-Type': types[path.extname(f)] || 'application/octet-stream' });
    return res.end(fs.readFileSync(f));
  }
  stats.calls++;
  let body = '';
  for await (const c of req) body += c;
  const data = body ? JSON.parse(body) : {};
  const auth = req.headers.authorization === `Bearer ${TOKEN}`;
  if (req.headers.authorization && !auth) return send(res, 401, { message: 'Bad credentials' });
  const p = u.pathname.replace('/api/repos/GermanyMayank/temporary-data', '');
  const write = req.method !== 'GET';
  if (write && !auth) return send(res, 404, { message: 'Not Found' });

  if (p === '' ) return send(res, 200, { permissions: { push: auth } });
  if (p.startsWith('/contents/') && req.method === 'GET') {
    const t = curTree(); const fp = p.slice(10);
    if (!t || !t.has(fp)) return send(res, 404, { message: 'Not Found' });
    return send(res, 200, { content: blobs.get(t.get(fp)), sha: t.get(fp) });
  }
  if (p.startsWith('/contents/') && req.method === 'PUT') {
    const fp = p.slice(10); const t = new Map(curTree() || []);
    if (t.has(fp) && !data.sha) return send(res, 422, { message: 'sha wasn\'t supplied' });
    t.set(fp, addBlob(data.content));
    const c = addCommit(addTree(t)); head = c;
    return send(res, 201, { content: { sha: t.get(fp) }, commit: { sha: c } });
  }
  if (p === '/git/ref/heads/main') {
    if (req.method === 'PATCH') { if (!commits.has(data.sha)) return send(res, 422, {}); head = data.sha; return send(res, 200, { object: { sha: head } }); }
    if (!head) return send(res, 409, { message: 'Git Repository is empty.' });
    const etag = `"${head}"`;
    if (req.headers['if-none-match'] === etag) { res.writeHead(304); return res.end(); }
    return send(res, 200, { object: { sha: head } }, { ETag: etag, 'Access-Control-Expose-Headers': 'ETag' });
  }
  if (p === '/git/refs/heads/main' && req.method === 'PATCH') {
    if (!commits.has(data.sha)) return send(res, 422, {}); head = data.sha; return send(res, 200, { object: { sha: head } });
  }
  if (p.startsWith('/git/trees/') && req.method === 'GET') {
    const cs = p.slice(11); const t = trees.get(commits.get(cs));
    if (!t) return send(res, 404, {});
    return send(res, 200, { tree: [...t].map(([path, s]) => ({ path, sha: s, type: 'blob' })) });
  }
  if (p.startsWith('/git/blobs/') && req.method === 'GET') {
    const b = blobs.get(p.slice(11)); return b ? send(res, 200, { content: b }) : send(res, 404, {});
  }
  if (p === '/git/blobs') return send(res, 201, { sha: addBlob(data.content) });
  if (p === '/git/trees') return send(res, 201, { sha: addTree(new Map(data.tree.map((e) => [e.path, e.sha]))) });
  if (p === '/git/commits') return send(res, 201, { sha: addCommit(data.tree) });
  return send(res, 404, { message: 'mock: ' + req.method + ' ' + p });
});

export function start(port = 8090) { return new Promise((r) => server.listen(port, () => r(server))); }
export const _state = { blobs, get head() { return head; }, curTree };
