'use strict';

const express = require('express');
const crypto = require('crypto');
const ejs = require('ejs');
const fs = require('fs');
const path = require('path');

const EJS_VERSION = require('ejs/package.json').version;

const app = express();
const PORT = Number(process.env.PORT || 12756);
const VIEWS = path.join(__dirname, 'views');

const SECRET = crypto.randomBytes(Number(process.env.SECRET_LEN || 21));

const FLAG_PATH = process.env.FLAG_PATH || '/flag.txt';

const config = Object.freeze({
  region: 'kr',
  maxSeat: 500,
  devtools: false,
});

app.use(express.json({ limit: '64kb' }));
app.use(express.urlencoded({ extended: false }));

app.use((req, res, next) => {
  res.setHeader('Server', `node/${process.versions.node} express/4 ejs/${EJS_VERSION}`);
  next();
});

const BASE_PROTO_KEYS = new Set(Object.getOwnPropertyNames(Object.prototype));
setInterval(() => {
  for (const k of Object.getOwnPropertyNames(Object.prototype)) {
    if (!BASE_PROTO_KEYS.has(k)) delete Object.prototype[k];
  }
}, 1000);

function protoSnapshot() {
  return new Set(Object.getOwnPropertyNames(Object.prototype));
}

function restoreProto(snap) {
  for (const k of Object.getOwnPropertyNames(Object.prototype)) {
    if (!snap.has(k)) delete Object.prototype[k];
  }
}

const PASS_SPEC = "pass = base64url(payload) '.' hex(sha256(SECRET || payload))";

function sign(payloadBuf) {
  return crypto.createHash('sha256')
    .update(Buffer.concat([SECRET, payloadBuf]))
    .digest('hex');
}

function makePass(payloadBuf) {
  return payloadBuf.toString('base64url') + '.' + sign(payloadBuf);
}

function openPass(cookie) {
  if (typeof cookie !== 'string' || cookie.length === 0) {
    return { ok: false, code: 'NO_PASS', msg: '입장권 쿠키(pass)가 없습니다' };
  }
  const dot = cookie.lastIndexOf('.');
  if (dot < 0) {
    return { ok: false, code: 'BAD_FORMAT', msg: `형식이 올바르지 않습니다. ${PASS_SPEC}` };
  }
  let payload;
  try {
    payload = Buffer.from(cookie.slice(0, dot), 'base64url');
  } catch (e) {
    return { ok: false, code: 'BAD_BASE64', msg: 'payload 를 base64url 로 디코드하지 못했습니다' };
  }
  const mac = cookie.slice(dot + 1);
  if (!/^[0-9a-fA-F]{64}$/.test(mac)) {
    return {
      ok: false, code: 'BAD_MAC_FORMAT',
      msg: 'mac 은 sha256 hex 64자여야 합니다',
      got_length: mac.length,
    };
  }
  if (sign(payload) !== mac.toLowerCase()) {
    return {
      ok: false, code: 'SIG_MISMATCH',
      msg: '서명이 일치하지 않습니다',
      spec: PASS_SPEC,
      payload_len: payload.length,
    };
  }
  return { ok: true, payload };
}

function parsePass(payloadBuf) {
  const out = Object.create(null);
  const s = payloadBuf.toString('latin1');
  for (const kv of s.split('&')) {
    const i = kv.indexOf('=');
    if (i < 0) continue;
    const k = kv.slice(0, i);
    const v = kv.slice(i + 1);
    if (k === 'seat') {
      if (out.seat === undefined) out.seat = v;
    } else {
      out[k] = v;
    }
  }
  return out;
}

function readCookie(req, name) {
  const raw = req.headers.cookie;
  if (!raw) return undefined;
  for (const part of raw.split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    if (part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return undefined;
}

function whoami(req) {
  const r = openPass(readCookie(req, 'pass'));
  if (!r.ok) return r;
  return { ok: true, payload: r.payload, me: parsePass(r.payload) };
}

function requireStaff(req, res, next) {
  const r = whoami(req);
  if (!r.ok) return res.status(401).json(Object.assign({ ok: false }, r));
  if (r.me.role !== 'staff') {
    return res.status(403).json({
      ok: false,
      code: 'NOT_STAFF',
      msg: '스태프 명단에 없습니다',
      need: { role: 'staff' },
      got: { role: r.me.role },
    });
  }
  req.me = r.me;
  next();
}

app.get('/', (req, res) => {
  const r = whoami(req);
  let me = r.ok ? r.me : null;
  if (!me) {
    const payload = Buffer.from('user=guest&role=member&seat=A11');
    res.setHeader('Set-Cookie',
      'pass=' + makePass(payload) + '; Path=/; SameSite=Lax');
    me = parsePass(payload);
  }
  res.type('html').send(page(`
    <p>오늘 공연은 매진입니다. 백스테이지는 <b>스태프 명단</b>에 있는 분만 들어갈 수 있어요.</p>
    <p>좋아하는 가수 이름만 캡션에 붙여도 알고리즘에 띄울 수 있대요!
       내가 좋아하는 가수를 무대에 올리려면, 명단에 내 이름부터 올려야겠죠.</p>

    <pre>${escapeHtml(PASS_SPEC)}
payload = ${escapeHtml(JSON.stringify(me))}</pre>

    <p class="mut">서버 구성은 응답의 <code>Server</code> 헤더에 적혀 있습니다.</p>

    <ul>
      <li><a href="/me">GET /me</a> — 내 입장권을 뜯어서 보여줍니다 (payload hex, mac 포함)</li>
      <li><a href="/setlist?id=1">GET /setlist?id=</a> — 셋리스트 열람</li>
      <li><a href="/replay?url=https://cdn.kctf.local/a.mp4">GET /replay?url=</a> — 클립 재업로드</li>
      <li>POST /soundcheck — 스태프 전용 리허설 미리보기.
          <b>application/json 본문은 템플릿 렌더 옵션에 반영됩니다.</b></li>
      <li>POST /devtools — 내부 도구. config.devtools 가 필요합니다.</li>
    </ul>
    <!--
      TIP: 이 캡션을 그대로 복붙하면 알고리즘이 띄워줍니다 -> "stepped into the crowd"
    -->
  `));
});

app.get('/me', (req, res) => {
  const r = whoami(req);
  if (!r.ok) return res.status(401).json(Object.assign({ ok: false }, r));

  const cookie = readCookie(req, 'pass');
  res.json({
    ok: true,
    pass: Object.assign({}, r.me),
    raw: {
      spec: PASS_SPEC,
      payload_hex: r.payload.toString('hex'),
      payload_len: r.payload.length,
      mac: cookie.slice(cookie.lastIndexOf('.') + 1),
    },
    parser: {
      format: 'key=value 를 & 로 이어붙인 문자열',
      role: '같은 키가 여러 번 오면 마지막 값이 이깁니다',
      seat: '같은 키가 여러 번 오면 첫 값이 이깁니다',
    },
  });
});

const SETLISTS = {
  1: { title: 'Opening', songs: ['LEMONADE', 'aespa'] },
  2: { title: 'Main', songs: ['RUDE!', 'Hearts2Hearts'] },
  7: { title: '???', songs: [] },
};

app.get('/setlist', (req, res) => {
  const id = String(req.query.id || '1');
  const item = SETLISTS[id];
  if (!item) return res.status(404).json({ ok: false, msg: 'no such setlist' });
  if (id === '7') {
    return res.type('html').send(page(`
      <h2 style="color:var(--acc)">RUDE! BACKSTAGE ACCESS GRANTED</h2>
      <p>백스테이지 입장이 승인되었습니다.</p>
      <p class="mut">…라고 적힌 안내판입니다. 그냥 안내판이에요.</p>
    `));
  }
  res.json({ ok: true, setlist: item });
});

const ALLOW_HOSTS = new Set(['cdn.kctf.local', 'img.kctf.local']);

app.get('/replay', (req, res) => {
  const raw = String(req.query.url || '');
  if (!/^https?:\/\//i.test(raw)) {
    return res.status(400).json({ ok: false, msg: 'http(s) 만 됩니다' });
  }
  let u;
  try {
    u = new URL(raw);
  } catch (e) {
    return res.status(400).json({ ok: false, msg: 'URL 파싱 실패' });
  }
  if (!ALLOW_HOSTS.has(u.hostname)) {
    return res.status(403).json({
      ok: false,
      msg: '이 URL은 아직 클라우드에 못 올라갔습니다.',
      host: u.hostname,
      allow: Array.from(ALLOW_HOSTS),
    });
  }
  res.json({ ok: true, msg: '이 URL은 이미 클라우드에 올라갔습니다.', host: u.hostname });
});

app.post('/devtools', requireStaff, (req, res) => {
  if (config.devtools) {
    return res.type('text').send(String(new Function(String(req.body.code))()));
  }
  return res.status(403).json({
    ok: false,
    code: 'DEVTOOLS_OFF',
    msg: '여기 캡션 붙여넣어도 아무일도 안일어나요 ㅎㅎ..',
    hint: 'config 는 기동 시 고정됩니다',
  });
});

const SOUNDCHECK_TPL = fs.readFileSync(path.join(VIEWS, 'soundcheck.ejs'), 'utf8');

function deepMerge(dst, src) {
  for (const k in src) {
    const v = src[k];
    if (v && typeof v === 'object') {
      if (!dst[k] || typeof dst[k] !== 'object') dst[k] = {};
      deepMerge(dst[k], v);
    } else {
      dst[k] = v;
    }
  }
  return dst;
}

app.post('/soundcheck', requireStaff, (req, res) => {
  const snap = protoSnapshot();
  try {
    const opts = { filename: path.join(VIEWS, 'soundcheck.ejs'), cache: false };
    deepMerge(opts, req.body || {});

    const keys = Object.keys(opts);
    res.setHeader('X-Render-Options', keys.join(','));

    const data = {
      who: String(req.me.user || 'staff'),
      seat: String(req.me.seat || '-'),
      region: config.region,
      opts: keys.join(', '),
      engine: 'ejs ' + EJS_VERSION,
    };

    return res.type('html').send(ejs.render(SOUNDCHECK_TPL, data, opts));
  } catch (e) {
    return res.status(500).json({
      ok: false,
      code: 'RENDER_FAILED',
      error: String(e && e.message),
      engine: 'ejs ' + EJS_VERSION,
    });
  } finally {
    restoreProto(snap);
  }
});

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

function page(body) {
  return `<!doctype html><html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>stepped into the crowd</title><style>
:root{--bg:#101215;--fg:#e7e7e7;--mut:#868d97;--line:#23272d;--acc:#c9a227}
body{margin:0;background:var(--bg);color:var(--fg);font-family:system-ui,"Apple SD Gothic Neo",sans-serif;line-height:1.65}
.wrap{max-width:660px;margin:0 auto;padding:34px 20px 64px}
h1{font-size:19px;margin:0 0 6px;font-weight:600}
h2{font-size:17px}
.sub{color:var(--mut);font-size:13px;border-bottom:1px solid var(--line);padding-bottom:16px;margin-bottom:24px}
pre{white-space:pre-wrap;word-break:break-all;font-size:12px;color:var(--mut);background:#0b0d10;padding:11px;border-radius:6px;border:1px solid var(--line)}
code{font-size:12px;color:var(--acc)}
a{color:var(--acc);text-decoration:none}a:hover{text-decoration:underline}
.mut{color:var(--mut);font-size:13px}
ul{padding-left:18px;font-size:14px}li{margin:5px 0}
</style></head><body><div class="wrap">
<h1>stepped into the crowd</h1>
<div class="sub">매진된 공연, 잠긴 백스테이지</div>
${body}
</div></body></html>`;
}

app.listen(PORT, '0.0.0.0', () => {
  console.log('[*] listening on ' + PORT);
  console.log('[*] secret length = ' + SECRET.length + ' (비공개)');
  console.log('[*] flag path = ' + FLAG_PATH);
});