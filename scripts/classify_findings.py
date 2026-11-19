#!/usr/bin/env python3
"""Assign a root cause to every parser disagreement found by analyze_fuzzing.py --replay.

Model: a lenient "union grammar" lexer that accepts everything either parser accepts and
records each differential feature with its byte offset (e.g. a control byte cJSON treats as
whitespace, a lone surrogate json-c replaces with U+FFFD), plus output models of how cJSON
1.7.19 and json-c 0.16 (JSON_TOKENER_STRICT) serialize numbers, strings and duplicate keys.

Acceptance differences: the primary cause is the earliest-offset feature the rejecting
parser cannot handle (ties: ACCEPT_PRECEDENCE). It is confirmed by a counterfactual: only
that feature is repaired and both real binaries are re-run; then all remaining features are
repaired until both parsers agree. Value differences: the models must reproduce both
parsers' actual outputs exactly; each rule is then enabled alone to see which ones explain
the difference (primary = first in VALUE_PRECEDENCE).

Run inside the AFL++ container (it executes the plain-clang wrappers):
    python3 scripts/classify_findings.py --analysis results/fuzz_analysis_v2_fixed \
        --fuzz-dir fuzz_out_v2 --bin-dir bin_v2
Writes <analysis>/root_causes.csv and <analysis>/classified.json (or --output-dir).
"""
from pathlib import Path
import re, math
from decimal import getcontext
import decimal
getcontext().prec = 5000; getcontext().Emax = decimal.MAX_EMAX; getcontext().Emin = decimal.MIN_EMIN
STDWS = b' \t\n\r'
HEX = b'0123456789abcdefABCDEF'
NUMRE = re.compile(rb'-?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?')
JC_DEPTH = 32      # json-c fails if a value has >= 32 enclosing containers
CJ_DEPTH = 1000    # cJSON fails if a value has >= 1000 enclosing containers

class ParseFail(Exception): pass

class Feat:
    def __init__(s, off, cause, side, repair, detail=''):
        s.off, s.cause, s.side, s.repair, s.detail = off, cause, side, repair, detail
    def __repr__(s): return f'{s.cause}@{s.off}'

class P:
    def __init__(s, d):
        s.d = d; s.i = 0; s.f = []
    def feat(s, *a, **k): s.f.append(Feat(*a, **k))
    def ws(s):
        d = s.d
        while s.i < len(d) and d[s.i] <= 0x20:
            b = d[s.i]
            if b not in STDWS:
                cause = 'CTRL_WS_NUL' if b == 0 else 'CTRL_WS_FORMFEED' if b == 0x0c else 'CTRL_WS_OTHER'
                s.feat(s.i, cause, 'C_ONLY', ('sub', s.i, s.i+1, b' '), detail=hex(b))
            s.i += 1
    def parse(s):
        if s.d.startswith(b'\xef\xbb\xbf'):
            s.feat(0, 'BOM', 'C_ONLY', ('sub', 0, 3, b'   ')); s.i = 3
        s.ws(); v = s.value(0); s.ws()
        if s.i != len(s.d): raise ParseFail(f'trailing at {s.i}')
        # trailing classification for whitespace features
        last = s.lastval_end
        for f in s.f:
            if f.cause.startswith('CTRL_WS') and f.off >= last: f.detail += ' trailing'
        return v
    def value(s, depth):
        d, i = s.d, s.i
        if depth >= JC_DEPTH and not getattr(s, '_jcdepth', False):
            s._jcdepth = True; s.feat(i, 'DEPTH_JSONC_32', 'C_ONLY', None)
        if depth >= CJ_DEPTH: raise ParseFail('cjson depth')
        if i >= len(d): raise ParseFail('eof')
        c = d[i:i+1]
        if c == b'{': v = s.obj(depth)
        elif c == b'[': v = s.arr(depth)
        elif c == b'"': v = ('str',) + s.string(key=False)
        elif d.startswith(b'true', i): s.i += 4; v = ('lit', True)
        elif d.startswith(b'false', i): s.i += 5; v = ('lit', False)
        elif d.startswith(b'null', i): s.i += 4; v = ('lit', None)
        elif d.startswith(b'NaN', i) or d.startswith(b'Infinity', i) or d.startswith(b'-Infinity', i):
            tok = re.match(rb'NaN|-?Infinity', d[i:]).group()
            s.feat(i, 'NAN_INFINITY', 'J_ONLY', ('sub', i, i+len(tok), b'0' + b' '*(len(tok)-1)))
            s.i += len(tok); v = ('special', tok)
        else:
            m = NUMRE.match(d, i)
            if not m: raise ParseFail(f'bad value at {i}')
            tok = m.group(); s.i = m.end()
            if b'.' not in tok and b'e' not in tok and b'E' not in tok and tok[0:1] == b'0' and int(tok) != 0:
                z = len(tok) - len(tok.lstrip(b'0'))
                s.feat(i, 'LEADING_ZERO', 'C_ONLY', ('sub', i, i+z, b' '*z))
            v = ('num', tok, i)
        s.lastval_end = s.i
        return v
    def obj(s, depth):
        s.i += 1; s.ws(); pairs = []
        if s.d[s.i:s.i+1] == b'}': s.i += 1; return ('obj', pairs)
        while True:
            s.ws()
            c = s.d[s.i:s.i+1]
            koff = s.i
            if c == b'"': k = s.string(key=True)
            elif c == b"'":
                k = s.squote_key()
            else: raise ParseFail(f'bad key at {s.i}')
            s.ws()
            if s.d[s.i:s.i+1] != b':': raise ParseFail(f'no colon at {s.i}')
            s.i += 1; s.ws()
            v = s.value(depth+1); pairs.append((k, v, koff)); s.ws()
            c = s.d[s.i:s.i+1]; s.i += 1
            if c == b'}': return ('obj', pairs)
            if c != b',': raise ParseFail(f'bad obj sep at {s.i-1}')
    def arr(s, depth):
        s.i += 1; s.ws(); items = []
        if s.d[s.i:s.i+1] == b']': s.i += 1; return ('arr', items)
        while True:
            s.ws(); items.append(s.value(depth+1)); s.ws()
            c = s.d[s.i:s.i+1]; s.i += 1
            if c == b']': return ('arr', items)
            if c != b',': raise ParseFail(f'bad arr sep at {s.i-1}')
    def squote_key(s):
        # json-c (even STRICT) accepts single-quoted object keys; content up to next unescaped quote
        start = s.i; d = s.d; j = start + 1; out = bytearray()
        while j < len(d) and d[j] != 0x27:
            if d[j] == 0x5c: j += 2
            else: out.append(d[j]); j += 1
        if j >= len(d): raise ParseFail('unterminated squote')
        inner = d[start+1:j]
        rep = b'"' + inner.replace(b'"', b'_') + b'"'
        s.feat(start, 'SINGLE_QUOTE_KEY', 'J_ONLY', ('sub', start, j+1, rep))
        s.i = j + 1
        return (bytes(out).split(b'\0')[0], bytes(out).split(b'\0')[0], False)
    def string(s, key):
        """Returns (cjson_bytes, jsonc_bytes, jsonc_ok). cjson_bytes truncated at first NUL (C string)."""
        d = s.d; start = s.i; j = start + 1
        # cJSON end-of-string scan (backslash skips next byte)
        while j < len(d) and d[j] != 0x22:
            if d[j] == 0x5c: j += 1
            j += 1
        if j >= len(d): raise ParseFail('unterminated string')
        end = j
        cj = bytearray(); jc = bytearray(); p = start + 1
        def u(x):
            return chr(x).encode('utf-8', 'surrogatepass')
        while p < end:
            b = d[p]
            if b != 0x5c:
                if b == 0:
                    s.feat(p, 'RAW_NUL_IN_STRING', 'C_ONLY', ('sub', p, p+1, b'x'))
                cj.append(b); jc.append(b); p += 1; continue
            e = d[p+1]
            simple = {0x62: 8, 0x66: 12, 0x6e: 10, 0x72: 13, 0x74: 9, 0x22: 0x22, 0x5c: 0x5c, 0x2f: 0x2f}
            if e in simple:
                cj.append(simple[e]); jc.append(simple[e]); p += 2; continue
            if e != 0x75: raise ParseFail(f'bad escape at {p}')
            if end - p < 6: raise ParseFail(f'short \\u at {p}')
            h = d[p+2:p+6]
            if not all(x in HEX for x in h):
                s.feat(p, 'INVALID_U_ESCAPE', 'C_ONLY', ('sub', p, p+6, b'\\u0041'), detail=repr(h))
                cj.append(0); p += 6; continue  # cJSON parse_hex4 -> 0 -> NUL
            cp = int(h, 16)
            if 0xDC00 <= cp <= 0xDFFF:
                s.feat(p, 'LONE_SURROGATE', 'J_ONLY', ('sub', p, p+6, b'\\u0041'), detail='lone low')
                jc += u(0xFFFD); p += 6; continue
            if 0xD800 <= cp <= 0xDBFF:
                q = p + 6
                h2 = d[q+2:q+6]
                if end - q >= 6 and d[q:q+2] == b'\\u' and all(x in HEX for x in h2) and 0xDC00 <= int(h2, 16) <= 0xDFFF:
                    c2 = 0x10000 + (((cp & 0x3FF) << 10) | (int(h2, 16) & 0x3FF))
                    cj += u(c2); jc += u(c2); p += 12; continue
                det = 'high + non-\\u' if d[q:q+2] != b'\\u' else 'high + non-low \\u'
                s.feat(p, 'LONE_SURROGATE', 'J_ONLY', ('sub', p, p+6, b'\\u0041'), detail=det)
                jc += u(0xFFFD); p += 6; continue
            if cp == 0:
                if not key: s.feat(p, 'U0000_VALUE', 'VALUE', None)
            cj += u(cp); jc += u(cp); p += 6
        s.i = end + 1
        cjb = bytes(cj).split(b'\0')[0]
        jcb = bytes(jc).split(b'\0')[0] if key else bytes(jc)
        return (cjb, jcb, True)

def lex(data):
    p = P(data)
    try:
        ast = p.parse(); return ast, p.f, None
    except (ParseFail, IndexError, ValueError, RecursionError) as e:
        return None, p.f, str(e)
"""Output models + lenient output parser for value-difference attribution."""
from collections import defaultdict
INT64_MAX, INT64_MIN, UINT64_MAX = 2**63-1, -2**63, 2**64-1

def exact(tok):
    """exact decimal value of a lenient numeric token as (neg, significant digits, exponent);
    unbounded exponent (same idea as the analyzer's JSONNumber), accepts '1.', '-.5', '068e1'."""
    t = tok.decode() if isinstance(tok, bytes) else tok
    neg = t.startswith('-'); t = t.lstrip('-')
    mant, _, ex = t.replace('E', 'e').partition('e')
    ip, _, fp = mant.partition('.')
    digits = (ip + fp).lstrip('0')
    if not digits: return ('num', (False, '0', 0))
    e = int(ex or '0') - len(fp)
    sig = digits.rstrip('0'); e += len(digits) - len(sig)
    return ('num', (neg, sig, e))

def exact_int(v): return exact(str(v))

def num_value_cmp(tok):
    """(is_int_form, python int value or None if huge-exponent)"""
    t = tok.decode(); isint = not any(ch in t for ch in '.eE')
    return isint, (int(t) if isint else None)

def num_category(tok):
    t = tok.decode()
    isint, v = num_value_cmp(tok)
    f = float(t)
    if isint and (v > INT64_MAX or v < INT64_MIN): return 'BIGINT_BEYOND_INT64'
    if math.isinf(f): return 'EXP_OVERFLOW'
    if f == 0 and exact(tok)[1][1] != '0': return 'EXP_UNDERFLOW'
    if isint and abs(v) >= 2**53: return 'BIGINT_PRECISION'
    return 'DECIMAL_PRECISION'

def cj_number(tok):
    d = float(tok.decode())
    if math.isinf(d) or math.isnan(d): return ('null',)
    vi = 2**31-1 if d >= 2**31-1 else -2**31 if d <= -2**31 else int(d)
    if d == vi: s = '%d' % vi
    else:
        s = '%1.15g' % d
        t = float(s)  # cJSON compare_double: relative DBL_EPSILON tolerance, not exact round-trip
        if not abs(t - d) <= max(abs(t), abs(d)) * 2.220446049250313e-16: s = '%1.17g' % d
    return exact(s)

def jc_number(tok):
    t = tok.decode()
    if not any(ch in t for ch in '.eE'):
        v = int(t)
        if t.startswith('-'): v = max(INT64_MIN, min(INT64_MAX, v))
        else: v = min(UINT64_MAX, v)
        return exact(str(v))
    return exact(t)  # json-c re-emits the original token for doubles

ALL_RULES = ('DUPLICATE_KEYS', 'U0000_TRUNCATION', 'BIGINT_BEYOND_INT64', 'EXP_OVERFLOW',
             'EXP_UNDERFLOW', 'BIGINT_PRECISION', 'DECIMAL_PRECISION')

def build(node, parser, rules):
    """parser in 'c','j','n'(neutral). rules: set of enabled differential rules."""
    k = node[0]
    if k == 'obj':
        groups = defaultdict(list)
        for key, v, _ in node[1]:
            kb = key[1]  # key truncated at NUL in both parsers (json-c strdup / cJSON C string)
            groups[kb].append(build(v, parser, rules))
        if parser == 'j' and 'DUPLICATE_KEYS' in rules:
            groups = {kk: vv[-1:] for kk, vv in groups.items()}
        return ('object', tuple(sorted((kk, tuple(vv)) for kk, vv in groups.items())))
    if k == 'arr': return ('array', tuple(build(x, parser, rules) for x in node[1]))
    if k == 'str':
        if parser == 'c' and 'U0000_TRUNCATION' in rules: return ('string', node[1])
        return ('string', node[2])
    if k == 'lit':
        return ('null',) if node[1] is None else ('boolean', node[1])
    if k == 'special': return ('special', node[1])
    if k == 'num':
        cat = num_category(node[1])
        if cat in rules and parser != 'n':
            return cj_number(node[1]) if parser == 'c' else jc_number(node[1])
        return exact(node[1])
    raise ValueError(k)

# ---- lenient parser for actual stdout ----
class OP:
    def __init__(s, d): s.d = d; s.i = 0
    def ws(s):
        while s.i < len(s.d) and s.d[s.i] in b' \t\r\n': s.i += 1
    def parse(s):
        s.ws(); v = s.val(); s.ws()
        assert s.i == len(s.d), 'trailing'
        return v
    def val(s):
        d = s.d; c = d[s.i:s.i+1]
        if c == b'{':
            s.i += 1; s.ws(); groups = defaultdict(list)
            if d[s.i:s.i+1] == b'}': s.i += 1; return ('object', ())
            while True:
                s.ws(); k = s.string(); s.ws(); assert d[s.i:s.i+1] == b':'; s.i += 1; s.ws()
                groups[k].append(s.val()); s.ws(); c = d[s.i:s.i+1]; s.i += 1
                if c == b'}': return ('object', tuple(sorted((kk, tuple(vv)) for kk, vv in groups.items())))
                assert c == b','
        if c == b'[':
            s.i += 1; s.ws(); items = []
            if d[s.i:s.i+1] == b']': s.i += 1; return ('array', ())
            while True:
                s.ws(); items.append(s.val()); s.ws(); c = d[s.i:s.i+1]; s.i += 1
                if c == b']': return ('array', tuple(items))
                assert c == b','
        if c == b'"': return ('string', s.string())
        for lit, v in ((b'true', ('boolean', True)), (b'false', ('boolean', False)), (b'null', ('null',))):
            if d.startswith(lit, s.i): s.i += len(lit); return v
        m = re.compile(rb'NaN|-?Infinity').match(d, s.i)
        if m: s.i = m.end(); return ('special', m.group())
        m = re.compile(rb'-?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?').match(d, s.i)
        assert m, f'bad at {s.i}'
        s.i = m.end(); return exact(m.group())
    def string(s):
        d = s.d; assert d[s.i] == 0x22; s.i += 1; out = bytearray()
        simple = {0x62: 8, 0x66: 12, 0x6e: 10, 0x72: 13, 0x74: 9, 0x22: 0x22, 0x5c: 0x5c, 0x2f: 0x2f}
        while d[s.i] != 0x22:
            b = d[s.i]
            if b == 0x5c:
                e = d[s.i+1]
                if e in simple: out.append(simple[e]); s.i += 2
                else:
                    cp = int(d[s.i+2:s.i+6], 16); s.i += 6
                    if 0xD800 <= cp <= 0xDBFF and d[s.i:s.i+2] == b'\\u':
                        c2 = int(d[s.i+2:s.i+6], 16); s.i += 6
                        cp = 0x10000 + (((cp & 0x3FF) << 10) | (c2 & 0x3FF))
                    out += chr(cp).encode('utf-8', 'surrogatepass')
            else: out.append(b); s.i += 1
        s.i += 1
        return bytes(out)

def parse_out(b):
    return OP(b.rstrip(b'\n')).parse()

# ================= driver =================
import argparse, base64, csv, json, os, subprocess, sys, tempfile, threading
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

BIN = {}
TMP_DIR = None


def run(data, w):
    fd, p = tempfile.mkstemp(dir=TMP_DIR)
    os.write(fd, data)
    os.close(fd)
    try:
        try:
            r = subprocess.run([BIN[w], p], capture_output=True, timeout=5)
        except subprocess.TimeoutExpired as exc:
            # Treat a hang as a rejection with a marker so the record is still classified.
            return False, exc.stdout or b'', (exc.stderr or b'') + b'\nTIMEOUT'
    finally:
        os.unlink(p)
    return r.returncode == 0, r.stdout, r.stderr



# Acceptance: features are ordered by input offset; this list breaks same-offset ties.
ACCEPT_PRECEDENCE = ['BOM', 'DEPTH_JSONC_32', 'CTRL_WS', 'LEADING_ZERO', 'RAW_NUL_IN_STRING',
                     'INVALID_U_ESCAPE', 'LONE_SURROGATE', 'NAN_INFINITY', 'SINGLE_QUOTE_KEY']
VALUE_PRECEDENCE = list(ALL_RULES)

LABELS = {
    'RAW_NUL_IN_STRING': 'Raw NUL byte inside a string (cJSON truncates)',
    'INVALID_U_ESCAPE': 'Invalid \\u escape (cJSON decodes as NUL, truncates)',
    'CTRL_WS': 'Control byte 0x00-0x20 used as whitespace',
    'LEADING_ZERO': 'Integer with leading zero',
    'LONE_SURROGATE': 'Lone/invalid UTF-16 surrogate (json-c -> U+FFFD)',
    'SINGLE_QUOTE_KEY': 'Single-quoted object key',
    'NAN_INFINITY': 'NaN / Infinity literal',
    'BOM': 'UTF-8 byte order mark',
    'DEPTH_JSONC_32': 'Nesting deeper than json-c limit (32)',
    'DUPLICATE_KEYS': 'Duplicate object keys (cJSON keeps all, json-c last)',
    'U0000_TRUNCATION': '\\u0000 in string value (cJSON truncates)',
    'BIGINT_BEYOND_INT64': 'Integer beyond int64 (json-c: uint64 or clamped; cJSON: double)',
    'BIGINT_PRECISION': 'Integer of 2^53 or more (cJSON prints 15-17 digits)',
    'EXP_OVERFLOW': 'Exponent overflow (both hold inf; cJSON prints null)',
    'EXP_UNDERFLOW': 'Exponent underflow (both hold 0; cJSON prints 0)',
    'DECIMAL_PRECISION': 'Long decimal (json-c echoes source text; cJSON reprints the double)',
}
DIRECTIONS = {('accepted', 'rejected'): 'Only cJSON accepts', ('rejected', 'accepted'): 'Only json-c accepts',
              ('accepted', 'accepted'): 'Both accept, different value'}


def norm(c): return 'CTRL_WS' if c.startswith('CTRL_WS') else c


def apply(data, rep):
    _, a, b, s = rep
    return data[:a] + s + data[b:]


def classify_acceptance(data, c_ok, j_ok):
    side = 'C_ONLY' if c_ok else 'J_ONLY'
    chain, d, confirmed_first = [], data, None
    for _ in range(200):
        ast, feats, err = lex(d)
        fs = sorted((f for f in feats if f.side == side),
                    key=lambda f: (f.off, ACCEPT_PRECEDENCE.index(norm(f.cause))))
        if not fs: return chain, 'UNEXPLAINED', confirmed_first, err
        f = fs[0]; chain.append((norm(f.cause), f.cause, f.off, f.detail))
        if f.repair is None:  # depth: confirm by json-c diagnostic
            _, _, e = run(d, 'j')
            ok = b'nesting too deep' in e
            return chain, 'EXPLAINED' if ok else 'UNEXPLAINED', confirmed_first if confirmed_first is not None else ok, None
        if confirmed_first is None:
            nd = apply(d, f.repair)
        else:  # after the single-feature counterfactual, repair all remaining features at once
            nd, last = d, None
            for g in sorted((g for g in fs if g.repair), key=lambda g: -g.off):
                if last is not None and g.repair[2] > last: continue  # skip overlaps
                nd = apply(nd, g.repair); last = g.repair[1]
                chain.append((norm(g.cause), g.cause, g.off, g.detail))
        c2, _, _ = run(nd, 'c'); j2, _, _ = run(nd, 'j')
        if confirmed_first is None:
            # single-feature counterfactual: removing only the primary feature must flip the
            # rejecting parser to accept, or else expose a later differential feature
            confirmed_first = (c2 == j2) or bool([g for g in lex(nd)[1] if g.side == side and g.off >= f.off])
        d = nd
        if c2 == j2: return chain, 'EXPLAINED' if c2 else 'BOTH_REJECT_AFTER_REPAIR', confirmed_first, None
    return chain, 'UNEXPLAINED', confirmed_first, 'loop'

def classify_value(data, co, jo):
    ast, feats, err = lex(data)
    if ast is None: return [], 'UNEXPLAINED', 'lex:' + err
    try: ac, aj = parse_out(co), parse_out(jo)
    except Exception as e: return [], 'UNEXPLAINED', 'outparse:' + str(e)
    R = set(ALL_RULES)
    pc, pj = build(ast, 'c', R), build(ast, 'j', R)
    if (pc, pj) != (ac, aj):
        return [], 'MODEL_MISMATCH', f'c_ok={pc == ac} j_ok={pj == aj}'
    if build(ast, 'c', set()) != build(ast, 'j', set()):
        return [], 'MODEL_MISMATCH', 'neutral differs'
    active = [r for r in ALL_RULES if build(ast, 'c', {r}) != build(ast, 'j', {r})]
    return active, ('EXPLAINED' if active else ('NO_SEMANTIC_DIFF' if ac == aj else 'UNEXPLAINED')), None



def classify_record(r, fuzz_dir, paths):
    data = (fuzz_dir / r['origins'][0]['path']).read_bytes()
    co, jo = (base64.b64decode(r[k]['stdout_b64']) for k in ('parser1', 'parser2'))
    rec = dict(sha=r['sha256'], tags=r['tags'], cs=r['parser1']['status'], js=r['parser2']['status'],
               identical=co == jo, path=paths.get(r['sha256'], r['origins'][0]['path']), bytes=len(data))
    if 'ACCEPTANCE_DIFFERENCE' in r['tags']:
        chain, st, conf, err = classify_acceptance(data, rec['cs'] == 'accepted', rec['js'] == 'accepted')
        rec.update(kind='accept', primary=chain[0][0] if chain else 'UNEXPLAINED', chain=chain,
                   causes=sorted({c[0] for c in chain}), status=st, first_confirmed=conf, err=err)
    elif rec['cs'] == rec['js'] == 'accepted' and not rec['identical']:
        active, st, err = classify_value(data, co, jo)
        # 'repr_only' rows were not tagged VALUE_DIFFERENCE by the analyzer (e.g. json-c printed
        # invalid JSON such as `1.`); a cause found here is a value difference the analyzer missed.
        rec.update(kind='value' if 'VALUE_DIFFERENCE' in r['tags'] else 'repr_only_nonidentical',
                   primary=active[0] if active else st, causes=active, status=st, err=err)
    else:
        rec.update(kind='identical_output')
    return rec


def main():
    global TMP_DIR
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--analysis', type=Path, required=True, help='analyze_fuzzing.py --replay output directory')
    ap.add_argument('--fuzz-dir', type=Path, required=True, help='Campaign root the analysis was made from')
    ap.add_argument('--bin-dir', type=Path, required=True, help='Directory with cjson_parse and jsonc_parse')
    ap.add_argument('--output-dir', type=Path, help='Default: the --analysis directory')
    ap.add_argument('--workers', type=int, default=os.cpu_count() or 1)
    args = ap.parse_args()
    BIN.update(c=str(args.bin_dir / 'cjson_parse'), j=str(args.bin_dir / 'jsonc_parse'))
    for b in BIN.values():
        if not os.access(b, os.X_OK):
            sys.exit(f'Error: {b} missing or not executable (run inside the Linux container)')
    out_dir = args.output_dir or args.analysis
    out_dir.mkdir(parents=True, exist_ok=True)
    out_csv, out_json = out_dir / 'root_causes.csv', out_dir / 'classified.json'
    for p in (out_csv, out_json):
        if p.exists():
            sys.exit(f'Error: {p} already exists')
    paths = {r['sha256']: r['input_path'] for r in csv.DictReader(open(args.analysis / 'findings.csv'))}
    records = [r for r in map(json.loads, open(args.analysis / 'replay.jsonl')) if r['tags']]
    with tempfile.TemporaryDirectory(prefix='classify_') as tmp:
        TMP_DIR = tmp
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            out = list(pool.map(lambda r: classify_record(r, args.fuzz_dir, paths), records))
    out_json.write_text(json.dumps(out, default=str))
    with out_csv.open('w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['sha256', 'bytes', 'kind', 'direction', 'root_cause_id', 'root_cause', 'all_causes',
                    'status', 'input_path'])
        for r in out:
            if r['kind'] == 'identical_output' or r['primary'] in ('NO_SEMANTIC_DIFF',):
                continue
            w.writerow([r['sha'], r['bytes'], r['kind'], DIRECTIONS.get((r['cs'], r['js']), f"{r['cs']}/{r['js']}"),
                        r['primary'], LABELS.get(r['primary'], r['primary']), ';'.join(r.get('causes') or []),
                        r['status'], r['path']])
    for kind in ('accept', 'value', 'repr_only_nonidentical'):
        xs = [r for r in out if r['kind'] == kind]
        print(f'== {kind}: {len(xs)}  status={dict(Counter(r["status"] for r in xs))}')
        for dirn in sorted({(r['cs'], r['js']) for r in xs}):
            ys = [r for r in xs if (r['cs'], r['js']) == dirn]
            print(f'   {DIRECTIONS.get(dirn, dirn)}: {len(ys)} {Counter(r["primary"] for r in ys).most_common()}')
    print(f'Wrote {out_csv} and {out_json}')


if __name__ == '__main__':
    # The lexer recurses about two frames per nesting level and cJSON allows depth 1000.
    sys.setrecursionlimit(20000)
    threading.stack_size(64 * 1024 * 1024)
    main()
