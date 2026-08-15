'use strict';

/*
 * 배송 라벨 표현식 평가기.
 *
 * 라벨 문구에 {{ ... }} 로 식을 넣으면 발송 시점에 값이 채워진다.
 * 창고 직원이 임의 코드를 넣지 못하도록 문법 단계에서 다음을 막는다.
 *
 *   - 점 접근 (order.total)
 *   - 대괄호 접근 (order["total"])
 *   - 허용 목록에 없는 함수 호출
 *   - 40자를 넘는 문자열 리터럴
 *
 * 이름은 네임스페이스를 지원한다. 창고 코드가 길어져서 str:upper 처럼
 * 구획을 나눠 쓸 수 있게 해 두었다.
 */

const MAX_STRING = 40;
const MAX_STEPS = 2000;

const FUNCS = {
  upper: (s) => String(s).toUpperCase(),
  lower: (s) => String(s).toLowerCase(),
  concat: (...parts) => parts.map(String).join(''),
  len: (s) => String(s).length,
  repeat: (s, n) => String(s).repeat(Math.max(0, Math.min(20, Number(n) | 0))),
  pad: (s, n) => String(s).padStart(Math.max(0, Math.min(60, Number(n) | 0)), ' '),
  slice: (s, a, b) => String(s).slice(Number(a) | 0, Number(b) | 0),
  add: (a, b) => Number(a) + Number(b),
  mul: (a, b) => Number(a) * Number(b),
};

class EvalError extends Error {}

// ---------------------------------------------------------------------------
// tokenizer
// ---------------------------------------------------------------------------
function tokenize(source) {
  const tokens = [];
  let i = 0;

  while (i < source.length) {
    const ch = source[i];

    if (/\s/.test(ch)) { i++; continue; }

    if (ch === '.') {
      throw new EvalError('점 접근은 허용되지 않습니다');
    }
    if (ch === '[' || ch === ']') {
      throw new EvalError('대괄호 접근은 허용되지 않습니다');
    }

    if (ch === '"' || ch === "'") {
      const quote = ch;
      let value = '';
      i++;
      while (i < source.length && source[i] !== quote) {
        if (source[i] === '\\') {
          throw new EvalError('문자열 이스케이프는 허용되지 않습니다');
        }
        value += source[i];
        i++;
      }
      if (i >= source.length) throw new EvalError('문자열이 닫히지 않았습니다');
      i++;
      if (value.length > MAX_STRING) {
        throw new EvalError(`문자열은 ${MAX_STRING}자를 넘을 수 없습니다`);
      }
      tokens.push({ type: 'str', value });
      continue;
    }

    if (/[0-9]/.test(ch)) {
      let value = '';
      while (i < source.length && /[0-9]/.test(source[i])) { value += source[i]; i++; }
      tokens.push({ type: 'num', value: Number(value) });
      continue;
    }

    // 이름. 네임스페이스 구분자를 포함한다.
    if (/[A-Za-z_:]/.test(ch)) {
      let value = '';
      while (i < source.length && /[A-Za-z0-9_:]/.test(source[i])) { value += source[i]; i++; }
      tokens.push({ type: 'name', value });
      continue;
    }

    if (ch === '(' || ch === ')' || ch === ',') {
      tokens.push({ type: ch });
      i++;
      continue;
    }

    throw new EvalError(`허용되지 않는 문자입니다: ${ch}`);
  }

  return tokens;
}

// ---------------------------------------------------------------------------
// parser  ->  expr := name ( '(' args ')' )*   |   str   |   num
// ---------------------------------------------------------------------------
function parse(tokens) {
  let pos = 0;

  function peek() { return tokens[pos]; }
  function next() { return tokens[pos++]; }

  function parseArgs() {
    const args = [];
    if (peek() && peek().type === ')') { next(); return args; }
    for (;;) {
      args.push(parseExpr());
      const token = next();
      if (!token) throw new EvalError('괄호가 닫히지 않았습니다');
      if (token.type === ')') break;
      if (token.type !== ',') throw new EvalError('인자 구분이 잘못되었습니다');
    }
    return args;
  }

  function parseExpr() {
    const token = next();
    if (!token) throw new EvalError('식이 비어 있습니다');

    let node;
    if (token.type === 'str') node = { kind: 'str', value: token.value };
    else if (token.type === 'num') node = { kind: 'num', value: token.value };
    else if (token.type === 'name') node = { kind: 'name', value: token.value };
    else throw new EvalError('식을 해석할 수 없습니다');

    while (peek() && peek().type === '(') {
      next();
      node = { kind: 'call', callee: node, args: parseArgs() };
    }
    return node;
  }

  const root = parseExpr();
  if (pos !== tokens.length) throw new EvalError('식 뒤에 남는 내용이 있습니다');
  return root;
}

// ---------------------------------------------------------------------------
// evaluator
// ---------------------------------------------------------------------------
function evaluate(source, scope) {
  const ast = parse(tokenize(source));
  let steps = 0;

  // 네임스페이스를 구분자 단위로 따라 내려간다.
  function resolve(name) {
    const parts = name.split(':');
    let current = scope[parts[0]];
    if (current === undefined && FUNCS[parts[0]] !== undefined) {
      current = FUNCS[parts[0]];
    }
    for (let i = 1; i < parts.length; i++) {
      if (current === undefined || current === null) {
        throw new EvalError(`알 수 없는 이름입니다: ${name}`);
      }
      current = current[parts[i]];
    }
    if (current === undefined) throw new EvalError(`알 수 없는 이름입니다: ${name}`);
    return current;
  }

  function walk(node) {
    if (++steps > MAX_STEPS) throw new EvalError('식이 너무 복잡합니다');

    if (node.kind === 'str' || node.kind === 'num') return node.value;
    if (node.kind === 'name') return resolve(node.value);

    if (node.kind === 'call') {
      const args = node.args.map(walk);
      if (node.callee.kind === 'name' && !node.callee.value.includes(':')) {
        const fn = FUNCS[node.callee.value];
        if (typeof fn !== 'function') {
          throw new EvalError(`허용되지 않은 함수입니다: ${node.callee.value}`);
        }
        return fn(...args);
      }
      const target = walk(node.callee);
      if (typeof target !== 'function') {
        throw new EvalError('호출할 수 없는 값입니다');
      }
      return target(...args);
    }

    throw new EvalError('식을 해석할 수 없습니다');
  }

  return walk(ast);
}

function render(template, scope) {
  return String(template).replace(/\{\{([^}]*)\}\}/g, (whole, expr) => {
    const value = evaluate(expr.trim(), scope);
    return String(value);
  });
}

module.exports = { render, evaluate, EvalError, FUNCS };
