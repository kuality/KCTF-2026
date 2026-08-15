'use strict';

const express = require('express');
const crypto = require('crypto');

const ecdsa = require('./ecdsa');
const labels = require('./labels');

const app = express();
const PORT = Number(process.env.PORT || 12757);
const FLAG_PATH = process.env.FLAG_PATH || '/flag.txt';

// 발행 키. 배포 시드에서 결정적으로 만든다.
// 컨테이너가 재시작돼도 같은 키가 나오므로, 참가자가 이미 복구해 둔
// 개인키나 위조해 둔 회원증이 무효가 되지 않는다.
const SEED = process.env.MH_SEED
  ? Buffer.from(process.env.MH_SEED, 'utf8')
  : crypto.randomBytes(32);

const KEY = ecdsa.keypairFromSeed(SEED);
const NONCE_SECRET = ecdsa.nonceSecretFromSeed(SEED);

if (!process.env.MH_SEED) {
  console.log('[!] MH_SEED 가 없어 임시 키로 기동합니다 (개발용)');
}

// 머더헬프 회원 코드.
// 그린코드는 운영자이며 모든 회원의 최우선 보호 대상이다.
const GRADES = ['옐로코드', '퍼플코드', '레드코드', '그린코드'];

// 겉으로는 평범한 농업용품 판매 목록이다.
// 품번과 가격은 기존 문제와 동일하게 유지한다.
const ITEMS = {
  'A-01': {
    name: '고압 농업용 호스 20M',
    spec: '내압 편사 · 16mm',
    price: 12000,
  },
  'A-02': {
    name: '원예용 장삽',
    spec: '목재 자루 · 일반형',
    price: 18000,
  },
  'B-07': {
    name: '예초기 교체날 3도날',
    spec: '범용 규격',
    price: 9500,
  },
  'C-12': {
    name: '전지가위',
    spec: '과수원용 · 200mm',
    price: 23000,
  },
  'D-03': {
    name: '농업용 PP 포대 100매',
    spec: '중량물 포장용',
    price: 31000,
  },
};

app.use(express.json({ limit: '32kb' }));
app.use(express.urlencoded({ extended: false }));

app.use((req, res, next) => {
  res.setHeader('X-Powered-By', 'murthehelp');
  next();
});

// ---------------------------------------------------------------------------
// 회원증
// ---------------------------------------------------------------------------

function readCookie(req, name) {
  const raw = req.headers.cookie;

  if (!raw) {
    return undefined;
  }

  for (const part of raw.split(';')) {
    const i = part.indexOf('=');

    if (i < 0) {
      continue;
    }

    if (part.slice(0, i).trim() === name) {
      return part.slice(i + 1).trim();
    }
  }

  return undefined;
}

function parseFields(message) {
  const out = Object.create(null);

  for (const pair of String(message).split('&')) {
    const i = pair.indexOf('=');

    if (i < 0) {
      continue;
    }

    out[pair.slice(0, i)] = pair.slice(i + 1);
  }

  return out;
}

function openPass(cookie) {
  if (typeof cookie !== 'string' || !cookie.length) {
    return {
      ok: false,
      code: 'NO_PASS',
      msg: '발급된 회원증을 찾을 수 없습니다',
    };
  }

  const parts = cookie.split('.');

  if (parts.length !== 3) {
    return {
      ok: false,
      code: 'BAD_FORMAT',
      msg: '회원증 형식이 올바르지 않습니다',
      spec: 'pass = base64url(message) "." r "." s   (r, s 는 각각 64자리 hex)',
    };
  }

  let message;

  try {
    message = Buffer.from(parts[0], 'base64url').toString('utf8');
  } catch (err) {
    return {
      ok: false,
      code: 'BAD_BASE64',
      msg: '회원증 메시지를 디코드하지 못했습니다',
    };
  }

  if (!ecdsa.verify(KEY.Q, message, parts[1], parts[2])) {
    return {
      ok: false,
      code: 'BAD_SIGNATURE',
      msg: '회원증의 발행 서명을 확인할 수 없습니다',
    };
  }

  const fields = parseFields(message);

  if (!GRADES.includes(fields.grade)) {
    return {
      ok: false,
      code: 'BAD_GRADE',
      msg: '등록되지 않은 회원 코드입니다',
      grades: GRADES,
    };
  }

  return {
    ok: true,
    message,
    fields,
  };
}

function issuePass(user, grade) {
  const message =
    `user=${user}&grade=${grade}&issued=${Math.floor(Date.now() / 1000)}`;

  const sig = ecdsa.sign(
    KEY.d,
    NONCE_SECRET,
    message,
    message
  );

  return (
    Buffer.from(message, 'utf8').toString('base64url')
    + '.'
    + sig.r
    + '.'
    + sig.s
  );
}

function whoami(req) {
  return openPass(readCookie(req, 'pass'));
}

// ---------------------------------------------------------------------------
// routes
// ---------------------------------------------------------------------------

function dramaShopBody() {
  return `
    <style>
      .notice,.intro,.code-panel,.catalog,.terminal,blockquote{display:none!important}
      .wrap{width:min(1180px,calc(100% - 32px));padding:24px 0 60px}
      .shop-layout{display:grid;grid-template-columns:minmax(0,1fr) 280px;gap:20px}
      .shop-main,.side-panel section{border:1px solid #30342f;background:#111411}
      .shop-main{padding:0 18px 22px}.crumb{padding:13px 0;color:#6f756d;font:10px ui-monospace,monospace;border-bottom:1px solid #292e29}
      .category-row{display:flex;gap:0;padding:15px 0;border-bottom:1px solid #292e29;overflow:auto}
      .category{border:1px solid #343a33;border-right:0;background:#151915;color:#7e857b;padding:8px 16px;font-size:11px;white-space:nowrap}
      .category:last-child{border-right:1px solid #343a33}.category.active{background:#d7d9d1;color:#111;border-color:#d7d9d1}
      .list-head{height:58px;display:flex;align-items:center;justify-content:space-between}.list-head strong{font-size:15px}.list-head span{color:#697067;font:9px ui-monospace,monospace}
      .product-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:1px;background:#30342f;border:1px solid #30342f}
      .product-card{background:#101310;min-width:0}.product-image{height:170px;position:relative;display:grid;place-items:center;overflow:hidden;background:#d0d0c8}
      .product-image:before{content:"";position:absolute;inset:0;background:linear-gradient(135deg,rgba(255,255,255,.35),transparent 55%),repeating-linear-gradient(0deg,rgba(0,0,0,.025) 0,rgba(0,0,0,.025) 1px,transparent 1px,transparent 4px)}
      .image-code{position:absolute;left:10px;top:8px;color:#686b65;font:9px ui-monospace,monospace;z-index:2}
      .image-shape{display:block;position:relative;width:100px;height:12px;background:#4f544e;box-shadow:24px 17px 0 -3px #73786f;transform:rotate(-12deg)}
      .product-image-1 .image-shape{width:110px;height:55px;border:10px solid #596159;border-radius:50%;background:transparent;box-shadow:18px 2px 0 -8px #596159}
      .product-image-2 .image-shape{width:10px;height:115px;transform:rotate(35deg);box-shadow:0 -35px 0 18px #555b54}
      .product-image-3 .image-shape{width:105px;height:20px;border-radius:50%;box-shadow:none}
      .product-image-4 .image-shape{width:90px;height:8px;box-shadow:45px -12px 0 5px #555;transform:rotate(-25deg)}
      .product-image-5 .image-shape{width:80px;height:100px;background:#777b71;box-shadow:none;transform:none}
      .product-info{padding:13px 13px 15px}.item-number{color:#767d73;font:9px ui-monospace,monospace}.product-info h2{margin:4px 0 2px;color:#daddd6;font-size:13px}.product-info p{margin:0;color:#676d65;font-size:10px}
      .price-row{display:flex;justify-content:space-between;align-items:end;margin-top:16px}.price-row b{font-size:13px}.price-row span{color:#68745d;font-size:9px}
      .side-panel{display:flex;flex-direction:column;gap:12px}.side-panel section{padding:14px}.box-title{display:flex;justify-content:space-between;align-items:center;padding-bottom:10px;border-bottom:1px solid #2b302b;color:#858b82;font:10px ui-monospace,monospace;letter-spacing:.08em}
      .box-title b{display:grid;place-items:center;width:16px;height:16px;background:#a8352f;color:#fff;border-radius:50%;font-size:8px}.box-title em{color:#9b7b35;font-style:normal;font-size:8px}
      .status-dot{width:6px;height:6px;border-radius:50%;background:#91aa43}.member-code{display:flex;gap:11px;align-items:center;padding:17px 0}.code-badge{width:31px;height:31px;border-radius:50%;background:#c2a139;box-shadow:0 0 0 5px rgba(194,161,57,.09)}
      .member-code small,.member-code strong{display:block}.member-code small{color:#666d64;font:8px ui-monospace,monospace}.member-code strong{font:15px ui-monospace,monospace;color:#c7cbbf}
      .plain-link{display:block;border:1px solid #394038;padding:8px;text-align:center;color:#9ba194;font-size:10px}.plain-link:hover{background:#191d19;text-decoration:none}
      .side-panel p{color:#858b82;font-size:10px;line-height:1.55}.side-panel pre{white-space:pre-wrap;margin:10px 0;padding:10px;background:#090b09;border:1px solid #272b27;color:#95a477;font:9px/1.6 ui-monospace,monospace}
      .message-meta{display:flex;justify-content:space-between;margin-top:12px;color:#62685f;font:8px ui-monospace,monospace}.message-text{color:#b4b8af!important}.reply-state{padding-top:9px;border-top:1px dashed #30352f;color:#9b7b35;font-size:9px}
      @media(max-width:850px){.shop-layout{grid-template-columns:1fr}.side-panel{display:grid;grid-template-columns:repeat(2,1fr)}.product-grid{grid-template-columns:repeat(2,1fr)}}
      @media(max-width:560px){.wrap{width:min(100% - 20px,1180px)}.product-grid,.side-panel{grid-template-columns:1fr}.product-image{height:145px}}
    </style>
    <div class="shop-layout">
      <main class="shop-main">
        <div class="crumb">HOME &gt; 전체상품</div>
        <div class="category-row"><button class="category active">전체</button><button class="category">절단공구</button><button class="category">운반용품</button><button class="category">보호장비</button><button class="category">농업자재</button></div>
        <div class="list-head"><strong>전체상품</strong><span>${Object.keys(ITEMS).length} ITEMS</span></div>
        <div class="product-grid">
          ${Object.entries(ITEMS).map(([code, item], index) => `
            <article class="product-card"><div class="product-image product-image-${index + 1}"><span class="image-code">${code}</span><span class="image-shape"></span></div>
            <div class="product-info"><span class="item-number">${code}</span><h2>${item.name}</h2><p>${item.spec}</p><div class="price-row"><b>${item.price.toLocaleString()}원</b><span>재고 있음</span></div></div></article>
          `).join('')}
        </div>
      </main>
      <aside class="side-panel">
        <section><div class="box-title"><span>MEMBER</span><i class="status-dot"></i></div><div class="member-code"><span class="code-badge"></span><div><small>CURRENT CODE</small><strong>YELLOW</strong></div></div><a class="plain-link" href="/me">회원증 정보 확인</a></section>
        <section><div class="box-title"><span>QUICK ORDER</span></div><p>상품번호와 수량을 전송하면 서명된 영수증이 발행됩니다.</p><pre>POST /order\n{"code":"A-01","qty":1}</pre></section>
        <section><div class="box-title"><span>MESSAGE</span><b>1</b></div><div class="message-meta"><span>ORDER #771204</span><time>방금 전</time></div><p class="message-text">배송이 아직 안 왔는데, 정진만 씨한테 무슨 일 있습니까?</p><div class="reply-state">답변 대기 중</div></section>
        <section><div class="box-title"><span>WAREHOUSE</span><em>LOCKED</em></div><p>지하 창고 출고 라벨은 그린코드만 발행할 수 있습니다.</p><pre>POST /label\n{"template":"받는분 {{ upper(buyer) }}"}</pre><a class="plain-link" href="/label/help">라벨 작성 규정</a></section>
      </aside>
    </div>`;
}

app.get('/', (req, res) => {
  const me = whoami(req);

  if (!me.ok) {
    res.setHeader(
      'Set-Cookie',
      'pass='
      + issuePass(
        'guest' + crypto.randomInt(1000, 9999),
        '옐로코드'
      )
      + '; Path=/; SameSite=Lax'
    );
  }

  return res.type('html').send(page(dramaShopBody()));
});

app.get('/me', (req, res) => {
  const me = whoami(req);

  if (!me.ok) {
    return res.status(401).json(
      Object.assign({ ok: false }, me)
    );
  }

  const cookie = readCookie(req, 'pass');
  const parts = cookie.split('.');

  return res.json({
    ok: true,

    pass: Object.assign({}, me.fields),

    raw: {
      message: me.message,
      r: parts[1],
      s: parts[2],
    },

    note: '회원증과 거래 영수증은 동일한 발행 키로 서명됩니다',
  });
});

app.post('/order', (req, res) => {
  const me = whoami(req);

  if (!me.ok) {
    return res.status(401).json(
      Object.assign({ ok: false }, me)
    );
  }

  const code = String(
    (req.body && req.body.code) || ''
  );

  const qty = Math.max(
    1,
    Math.min(
      99,
      Number((req.body && req.body.qty) || 1) | 0
    )
  );

  const item = ITEMS[code];

  if (!item) {
    return res.status(404).json({
      ok: false,
      code: 'NO_ITEM',
      msg: '등록되지 않은 품번입니다',
      items: Object.keys(ITEMS),
    });
  }

  const seconds = Math.floor(Date.now() / 1000);
  const serial = crypto.randomInt(100000, 999999);

  const message =
    `receipt=${serial}`
    + `&code=${code}`
    + `&qty=${qty}`
    + `&total=${item.price * qty}`
    + `&at=${seconds}`;

  const sig = ecdsa.sign(
    KEY.d,
    NONCE_SECRET,
    message,
    message
  );

  return res.json({
    ok: true,

    receipt: {
      message,
      r: sig.r,
      s: sig.s,
    },

    note: '서명 검증 대상은 message 원문입니다',
  });
});

app.get('/label/help', (req, res) => {
  res.type('html').send(page(`
    <div class="manual-head">
      <span class="eyebrow">
        WAREHOUSE DOCUMENT MH-LABEL-04
      </span>

      <h2 class="manual-title">출고 라벨 작성 규정</h2>

      <p>
        지하 창고 자동 출고기에 전달되는 라벨 양식입니다.
        중괄호 안의 표현식은 라벨을 인쇄할 때 실제 값으로
        치환됩니다.
      </p>
    </div>

    <section class="manual-section">
      <div class="section-title">
        <div>
          <span class="eyebrow">AVAILABLE FIELDS</span>
          <h2>출고 정보</h2>
        </div>
      </div>

      <table>
        <tr>
          <th>이름</th>
          <th>인쇄되는 값</th>
        </tr>

        <tr>
          <td><code>buyer</code></td>
          <td>주문자 식별명</td>
        </tr>

        <tr>
          <td><code>grade</code></td>
          <td>주문자 코드 등급</td>
        </tr>

        <tr>
          <td><code>shop</code></td>
          <td>발송 상점명</td>
        </tr>

        <tr>
          <td><code>today</code></td>
          <td>출고 처리일</td>
        </tr>
      </table>
    </section>

    <section class="manual-section">
      <span class="eyebrow">APPROVED FUNCTIONS</span>
      <h2>허용된 처리 함수</h2>

      <div class="function-list">
        ${Object.keys(labels.FUNCS)
      .map(name => `<code>${name}</code>`)
      .join('')}
      </div>
    </section>

    <section class="manual-section regulation">
      <span class="eyebrow">RESTRICTIONS</span>
      <h2>보안 규정</h2>

      <ol>
        <li>
          점 접근과 대괄호 접근은 허용되지 않습니다.
        </li>

        <li>
          승인 목록에 없는 함수는 실행할 수 없습니다.
        </li>

        <li>
          문자열 리터럴의 최대 길이는 40자입니다.
        </li>

        <li>
          창고 식별자는 구획 단위로 관리됩니다.
        </li>
      </ol>
    </section>

    <div class="example">
      <span>LABEL EXAMPLE</span>
      <code>{{ concat("받는분 ", upper(buyer)) }}</code>
    </div>

    <p class="manual-quote">
      강한 자는 짖지 않는다. 출고 기록만 남긴다.
    </p>
  `));
});

app.post('/label', (req, res) => {
  const me = whoami(req);

  if (!me.ok) {
    return res.status(401).json(
      Object.assign({ ok: false }, me)
    );
  }

  if (me.fields.grade !== '그린코드') {
    return res.status(403).json({
      ok: false,
      code: 'GRADE_REQUIRED',
      msg: '지하 출고 구역은 그린코드만 사용할 수 있습니다',

      need: {
        grade: '그린코드',
      },

      got: {
        grade: me.fields.grade,
      },
    });
  }

  const template = String(
    (req.body && req.body.template) || ''
  );

  if (template.length > 400) {
    return res.status(400).json({
      ok: false,
      code: 'TOO_LONG',
      msg: '출고 라벨의 허용 길이를 초과했습니다',
    });
  }

  const scope = {
    buyer: String(me.fields.user || 'guest'),
    grade: String(me.fields.grade),
    shop: '머더헬프',
    today: new Date().toISOString().slice(0, 10),
  };

  try {
    return res.json({
      ok: true,
      label: labels.render(template, scope),
    });
  } catch (err) {
    return res.status(400).json({
      ok: false,

      code:
        err instanceof labels.EvalError
          ? 'EVAL_REJECTED'
          : 'EVAL_FAILED',

      msg: String(err && err.message),
    });
  }
});

// ---------------------------------------------------------------------------
// page
// ---------------------------------------------------------------------------

function page(body) {
  return `<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">

<meta
  name="viewport"
  content="width=device-width,initial-scale=1"
>

<title>MURTHEHELP — Agricultural Supply</title>

<style>
:root {
  --bg: #080a09;
  --panel: #101310;
  --panel-2: #151915;
  --fg: #e2e5df;
  --muted: #747b72;
  --line: #292e29;
  --green: #9fbd37;
  --green-dark: #53651e;
  --yellow: #d1a934;
  --red: #a94338;
  --purple: #76518d;
}

* {
  box-sizing: border-box;
}

html {
  min-height: 100%;
  background: var(--bg);
}

body {
  min-height: 100%;
  margin: 0;

  background:
    linear-gradient(
      rgba(255, 255, 255, .012) 1px,
      transparent 1px
    ),
    linear-gradient(
      90deg,
      rgba(255, 255, 255, .012) 1px,
      transparent 1px
    ),
    var(--bg);

  background-size: 32px 32px;

  color: var(--fg);
  font-family:
    "Pretendard",
    "Apple SD Gothic Neo",
    "Malgun Gothic",
    system-ui,
    sans-serif;

  line-height: 1.65;
}

a {
  color: inherit;
  text-decoration: none;
}

code,
.method,
.action,
.eyebrow,
.product-code,
.step {
  font-family:
    ui-monospace,
    SFMono-Regular,
    Menlo,
    Consolas,
    monospace;
}

.topbar {
  border-bottom: 1px solid var(--line);
  background: rgba(8, 10, 9, .94);
}

.topbar-inner {
  width: min(1100px, calc(100% - 40px));
  min-height: 72px;
  margin: 0 auto;

  display: flex;
  align-items: center;
  justify-content: space-between;
}

.brand {
  display: flex;
  align-items: center;
  gap: 13px;
}

.brand-mark {
  width: 35px;
  height: 35px;

  border: 1px solid var(--green);
  position: relative;
}

.brand-mark::before,
.brand-mark::after {
  content: "";
  position: absolute;
  background: var(--green);
}

.brand-mark::before {
  width: 17px;
  height: 1px;
  left: 8px;
  top: 16px;
}

.brand-mark::after {
  width: 1px;
  height: 17px;
  left: 16px;
  top: 8px;
}

.brand strong {
  display: block;

  font-size: 18px;
  line-height: 1;
  letter-spacing: .14em;
}

.brand small {
  display: block;
  margin-top: 5px;

  color: var(--muted);
  font-size: 9px;
  letter-spacing: .18em;
}

.connection {
  color: var(--muted);
  font-family: ui-monospace, monospace;
  font-size: 11px;
}

.connection b {
  color: var(--green);
  font-weight: 500;
}

.wrap {
  width: min(1100px, calc(100% - 40px));
  margin: 0 auto;
  padding: 42px 0 80px;
}

.notice {
  display: flex;
  gap: 15px;

  padding: 17px 19px;

  border: 1px solid #5d4c20;
  background: rgba(209, 169, 52, .06);

  font-size: 13px;
}

.notice-mark {
  color: var(--yellow);
  font-family: monospace;
  font-weight: 700;
}

.notice strong {
  color: #ddd2b4;
}

.notice p {
  margin: 3px 0 0;
  color: #8e8876;
}

.intro {
  max-width: 720px;
  padding: 65px 0 43px;
}

.eyebrow {
  margin: 0 0 10px;

  color: var(--green);
  font-size: 10px;
  letter-spacing: .18em;
}

.intro-title {
  margin: 0 0 20px;

  color: var(--fg);
  font-size: clamp(28px, 5vw, 48px);
  line-height: 1.2;
  letter-spacing: -.035em;
}

.intro p {
  color: #a7aca4;
}

.intro .system-line {
  color: var(--muted);
  font-size: 13px;
}

.code-panel,
.terminal {
  margin: 18px 0 58px;

  border: 1px solid var(--line);
  background: rgba(16, 19, 16, .92);
}

.code-head,
.terminal-head {
  min-height: 42px;
  padding: 0 16px;

  border-bottom: 1px solid var(--line);

  display: flex;
  align-items: center;
  justify-content: space-between;

  color: var(--muted);
  font-family: ui-monospace, monospace;
  font-size: 10px;
  letter-spacing: .15em;
}

.secure,
.online {
  color: var(--green);
}

.code-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
}

.code-card {
  min-height: 100px;
  padding: 20px;

  border-right: 1px solid var(--line);
}

.code-card:last-child {
  border-right: 0;
}

.code-card strong,
.code-card small {
  display: block;
}

.code-card strong {
  margin: 8px 0 2px;

  font-family: ui-monospace, monospace;
  font-size: 13px;
  letter-spacing: .1em;
}

.code-card small {
  color: var(--muted);
  font-size: 11px;
}

.code-dot {
  display: block;

  width: 7px;
  height: 7px;
  border-radius: 50%;
}

.red .code-dot {
  background: var(--red);
}

.purple .code-dot {
  background: var(--purple);
}

.yellow .code-dot {
  background: var(--yellow);
}

.green .code-dot {
  background: var(--green);
}

.policy {
  margin: 0;
  padding: 13px 16px;

  border-top: 1px solid var(--line);

  color: #8f958c;
  font-size: 12px;
}

.section-title {
  margin-bottom: 15px;

  display: flex;
  align-items: end;
  justify-content: space-between;
}

.section-title h2,
.manual-section h2 {
  margin: 0;
  font-size: 20px;
}

.stock {
  color: var(--muted);
  font-size: 11px;
}

.catalog {
  margin-bottom: 58px;

  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 1px;

  border: 1px solid var(--line);
  background: var(--line);
}

.product {
  min-height: 150px;

  display: grid;
  grid-template-columns: 115px 1fr;

  background: var(--panel);
}

.product-photo {
  border-right: 1px solid var(--line);

  display: grid;
  place-items: center;

  background:
    repeating-linear-gradient(
      -45deg,
      #111411,
      #111411 7px,
      #0d100d 7px,
      #0d100d 14px
    );

  color: #485047;
  font-family: ui-monospace, monospace;
  font-size: 10px;
}

.product-body {
  padding: 17px;
}

.product-code {
  color: var(--green);
  font-size: 9px;
  letter-spacing: .12em;
}

.product h3 {
  margin: 4px 0;
  font-size: 14px;
}

.product p {
  margin: 0;

  color: var(--muted);
  font-size: 11px;
}

.product-bottom {
  margin-top: 20px;

  display: flex;
  align-items: end;
  justify-content: space-between;
}

.product-bottom strong {
  font-size: 14px;
}

.product-bottom span {
  color: #68705f;
  font-size: 9px;
}

.terminal-row {
  min-height: 105px;
  padding: 18px;

  border-bottom: 1px solid var(--line);

  display: flex;
  justify-content: space-between;
  gap: 25px;
}

.terminal-row:last-child {
  border-bottom: 0;
}

.terminal-row strong {
  font-size: 13px;
}

.terminal-row p {
  margin: 4px 0;

  color: var(--muted);
  font-size: 11px;
}

.step {
  margin-right: 12px;

  color: #545b52;
  font-size: 10px;
}

code {
  color: #a8bd73;
  font-size: 11px;
  word-break: break-all;
}

.action,
.method {
  align-self: center;
  flex: 0 0 auto;

  padding: 8px 11px;

  border: 1px solid var(--green-dark);

  color: var(--green);
  font-size: 10px;
}

.action:hover {
  background: rgba(159, 189, 55, .08);
}

.locked {
  border-color: #54471f;
  color: var(--yellow);
}

blockquote {
  margin: 55px 0 0;
  padding: 22px 0 22px 22px;

  border-left: 2px solid var(--green);

  color: #92988f;
  font-size: 13px;
}

blockquote span {
  display: block;
  margin-bottom: 5px;

  color: var(--green);
  font-family: ui-monospace, monospace;
  font-size: 9px;
  letter-spacing: .15em;
}

.manual-head {
  max-width: 720px;
  padding: 30px 0 35px;
}

.manual-title {
  margin: 0;
  font-size: 32px;
}

.manual-head p {
  color: var(--muted);
}

.manual-section {
  margin: 25px 0;
  padding: 24px;

  border: 1px solid var(--line);
  background: var(--panel);
}

table {
  width: 100%;
  margin-top: 16px;

  border-collapse: collapse;

  font-size: 12px;
}

th,
td {
  padding: 11px 10px;

  border-bottom: 1px solid var(--line);

  text-align: left;
}

th {
  color: var(--muted);
  font-weight: 500;
}

.function-list {
  margin-top: 16px;

  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.function-list code {
  padding: 6px 9px;

  border: 1px solid var(--line);
  background: #0b0d0b;
}

.regulation ol {
  padding-left: 20px;

  color: #92988f;
  font-size: 12px;
}

.regulation li {
  margin: 8px 0;
}

.example {
  padding: 18px;

  border: 1px solid var(--green-dark);
  background: rgba(159, 189, 55, .04);
}

.example span {
  display: block;
  margin-bottom: 7px;

  color: var(--green);
  font-family: ui-monospace, monospace;
  font-size: 9px;
  letter-spacing: .14em;
}

.manual-quote {
  margin-top: 40px;

  color: #626961;
  font-size: 12px;
  text-align: center;
}

.footer {
  margin-top: 70px;
  padding-top: 16px;

  border-top: 1px solid var(--line);

  display: flex;
  justify-content: space-between;
  gap: 20px;

  color: #444a43;
  font-family: ui-monospace, monospace;
  font-size: 9px;
  letter-spacing: .1em;
}

@media (max-width: 700px) {
  .connection {
    display: none;
  }

  .wrap,
  .topbar-inner {
    width: min(100% - 28px, 1100px);
  }

  .code-grid {
    grid-template-columns: repeat(2, 1fr);
  }

  .code-card:nth-child(2) {
    border-right: 0;
  }

  .code-card:nth-child(-n + 2) {
    border-bottom: 1px solid var(--line);
  }

  .catalog {
    grid-template-columns: 1fr;
  }

  .terminal-row {
    flex-direction: column;
  }

  .action,
  .method {
    align-self: flex-start;
  }

  .footer {
    flex-direction: column;
  }
}
</style>
</head>

<body>
<header class="topbar">
  <div class="topbar-inner">
    <a class="brand" href="/">
      <span class="brand-mark"></span>

      <span>
        <strong>MURTHEHELP</strong>
        <small>AGRICULTURAL EQUIPMENT SUPPLY</small>
      </span>
    </a>

    <div class="connection">
      PRIVATE NETWORK &nbsp;
      <b>● CONNECTED</b>
    </div>
  </div>
</header>

<main class="wrap">
  ${body}

  <footer class="footer">
    <span>MH INTERNAL COMMERCE SYSTEM</span>
    <span>NO QUESTIONS · NO RETURNS</span>
  </footer>
</main>
</body>
</html>`;
}

// ---------------------------------------------------------------------------
// server
// ---------------------------------------------------------------------------

// 라벨 표현식은 임의 코드를 실행할 수 있는 구조다.
// 한 참가자가 프로세스를 죽여 다른 참가자를 막지 못하도록 방어한다.
process.on('uncaughtException', (err) => {
  console.error('[!] uncaught:', err && err.message);
});

process.on('unhandledRejection', (err) => {
  console.error('[!] unhandled:', err && err.message);
});

app.listen(PORT, '0.0.0.0', () => {
  console.log('[*] listening on ' + PORT);
  console.log('[*] flag path = ' + FLAG_PATH);
});