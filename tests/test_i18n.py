"""Kontroll av översättningen (svenska -> engelska) i netatlas.html och server/login.html.

    python tests/test_i18n.py            # kontrollera hela appen
    python tests/test_i18n.py del.js en.json [--mobile en-mobil.json]   # kontrollera en kodbit (används vid större ändringar)

Kontrollerar att
- varje tx('…') / tx`…` har en engelsk översättning (nyckeln är den svenska texten, värden blir {0}, {1} …),
- översättningen har samma {n} som nyckeln och inga raka citattecken (" eller '),
- inga svenska texter ligger kvar utanför tx() (heuristik; avsiktliga undantag står i TILLATNA nedan),
- fasta texter i sidans HTML (meny, verktygsfält) och etiketterna i tabellerna TYPES, SVC och FIELDS är översatta,
- inloggningssidan har en översättning för varje text."""
import html.parser
import json
import os
import re
import sys

PROJ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# svenska ord som sällan förekommer i kod eller engelska (används för att hitta oöversatta texter)
SV_ORD = re.compile(r'[åäöÅÄÖ]|\b(och|inte|för|att|med|eller|som|kan|finns|har|ingen|inga|spara|avbryt|saknas|kunde|'
                    r'hittades|ändra|lägg|visa|dölj|välj|skapa|radera|enhet|enheter|sedan|senaste|alla|nytt|nya|fel|'
                    r'klart|gång|dag|dagar|vecka|timme|timmar|minuter|sekunder|aldrig|okänd|okänt|ogiltig|ogiltigt|'
                    r'nätet|kopia|kopian|filen|filer|namn|typ|rum|plats|platser|jobb|konto|konton|tjänst|tjänster)\b', re.I)
# svenska texter som avsiktligt inte går genom tx() (t.ex. sökord som tolkas, filnamn)
TILLATNA = {
    'typ', 'rum', 'typ:',                                    # sökord i sökfältet (engelska alias: type:, room:)
    'med',                                                   # allvarlighetsgrad i Att göra (high/med/low)
    'Ogiltigt svar från hjälpprogrammet',                    # felmeddelanden från api() översätts med txs()
    'Ogiltigt svar från servern.', 'Kunde inte nå servern.',  # login.html: översätts via tx(lastErr = …)
}
TVASPRAKIGA = {'Språk / Language'}


# ---------------------------------------------------------------- JavaScript-läsare
class Lexer:
    """Enkel läsare för JavaScript: hittar strängar, mallar (`…`) och anrop av tx. Hoppar över kommentarer och regex."""
    KW_REGEX = {'return', 'typeof', 'case', 'do', 'else', 'in', 'of', 'new', 'delete', 'void', 'throw', 'instanceof',
                'yield', 'await'}

    def __init__(self, src, line0=1):
        self.s, self.n, self.line0 = src, len(src), line0
        self.strings = []   # (rad, text, i_tx) – alla strängar och malltexter
        self.calls = []     # (rad, nyckel eller None, form)
        self.err = []

    def line(self, i):
        return self.s.count('\n', 0, i) + self.line0

    def cook(self, raw):
        out, i = [], 0
        while i < len(raw):
            c = raw[i]
            if c != '\\':
                out.append(c); i += 1; continue
            i += 1
            if i >= len(raw):
                break
            c = raw[i]
            simple = {'n': '\n', 'r': '\r', 't': '\t', 'b': '\b', 'f': '\f', 'v': '\v', '0': '\0'}
            if c in simple and not (c == '0' and i + 1 < len(raw) and raw[i + 1].isdigit()):
                out.append(simple[c]); i += 1
            elif c == 'x':
                out.append(chr(int(raw[i + 1:i + 3], 16))); i += 3
            elif c == 'u':
                if raw[i + 1] == '{':
                    j = raw.index('}', i)
                    out.append(chr(int(raw[i + 2:j], 16))); i = j + 1
                else:
                    out.append(chr(int(raw[i + 1:i + 5], 16))); i += 5
            elif c == '\r':
                i += 2 if raw[i + 1:i + 2] == '\n' else 1
            elif c == '\n':
                i += 1
            else:
                out.append(c); i += 1
        return ''.join(out)

    def string(self, i):
        q, j = self.s[i], i + 1
        while j < self.n and self.s[j] != q:
            if self.s[j] == '\\':
                j += 1
            elif self.s[j] == '\n':
                self.err.append(f'rad {self.line(i)}: sträng utan slut')
                break
            j += 1
        return self.cook(self.s[i + 1:j]), j + 1

    def template(self, i):
        """Läser `…` från i (backtick). Returnerar (textdelar, antal uttryck, position efter)."""
        parts, cur, j = [], [], i + 1
        while j < self.n:
            c = self.s[j]
            if c == '\\':
                cur.append(self.s[j:j + 2]); j += 2; continue
            if c == '`':
                parts.append(self.cook(''.join(cur)))
                return parts, len(parts) - 1, j + 1
            if c == '$' and self.s[j + 1:j + 2] == '{':
                parts.append(self.cook(''.join(cur))); cur = []
                j = self.code(j + 2, closing=True)
                continue
            cur.append(c); j += 1
        self.err.append(f'rad {self.line(i)}: mall utan slut')
        return parts, 0, self.n

    def regex(self, i):
        j, cls = i + 1, False
        while j < self.n:
            c = self.s[j]
            if c == '\\':
                j += 2; continue
            if c == '[':
                cls = True
            elif c == ']':
                cls = False
            elif c == '/' and not cls:
                j += 1
                while j < self.n and (self.s[j].isalpha()):
                    j += 1
                return j
            elif c == '\n':
                break
            j += 1
        return j

    def code(self, i, closing=False):
        """Läser kod från i. closing=True: stannar efter den } som avslutar ett ${…}-uttryck."""
        depth, prev, prev_word = 0, '', ''
        while i < self.n:
            c = self.s[i]
            if c in ' \t\r\n':
                i += 1; continue
            if c == '/' and self.s[i + 1:i + 2] == '/':
                k = self.s.find('\n', i); i = self.n if k < 0 else k; continue
            if c == '/' and self.s[i + 1:i + 2] == '*':
                k = self.s.find('*/', i + 2); i = self.n if k < 0 else k + 2; continue
            if c in '\'"':
                txt, i2 = self.string(i)
                self.strings.append((self.line(i), txt, False))
                i, prev, prev_word = i2, 'x', ''; continue
            if c == '`':
                parts, nexp, i2 = self.template(i)
                for p in parts:
                    self.strings.append((self.line(i), p, False))
                i, prev, prev_word = i2, 'x', ''; continue
            if c == '/':
                if prev in ('', '(', ',', '=', ':', '[', '!', '&', '|', '?', '{', '}', ';', '+', '-', '*', '%', '<', '>', '~', '^') \
                        or prev_word in self.KW_REGEX:
                    i, prev, prev_word = self.regex(i), 'x', ''; continue
                i, prev, prev_word = i + 1, '/', ''; continue
            if c.isalpha() or c in '_$':
                j = i
                while j < self.n and (self.s[j].isalnum() or self.s[j] in '_$'):
                    j += 1
                word = self.s[i:j]
                b = i - 1
                while b >= 0 and self.s[b] in ' \t\r\n':
                    b -= 1
                before = self.s[b] if b >= 0 else ''
                if word == 'tx' and before != '.' and not self.s[max(0, i - 12):i].rstrip().endswith('function'):
                    k = j
                    while k < self.n and self.s[k] in ' \t':
                        k += 1
                    if self.s[k:k + 1] == '`':
                        parts, nexp, _ = self.template_tx(k)
                        key = ''.join(p + ('{%d}' % n if n < nexp else '') for n, p in enumerate(parts))
                        self.calls.append((self.line(i), key, 'tagg'))
                        j = _
                        i, prev, prev_word = j, 'x', ''; continue
                    if self.s[k:k + 1] == '(':
                        m = k + 1
                        while m < self.n and self.s[m] in ' \t\r\n':
                            m += 1
                        if self.s[m:m + 1] in '\'"':
                            txt, m2 = self.string(m)
                            self.calls.append((self.line(i), txt, 'sträng'))
                            self.strings.append((self.line(i), txt, True))
                            i, prev, prev_word = m2, 'x', ''; continue
                        if self.s[m:m + 1] == '`':
                            parts, nexp, m2 = self.template_tx(m)
                            if nexp:
                                self.calls.append((self.line(i), None, 'mall med ${} i tx(…) – använd tx`…` i stället'))
                            else:
                                self.calls.append((self.line(i), parts[0], 'sträng'))
                            i, prev, prev_word = m2, 'x', ''; continue
                        self.calls.append((self.line(i), None, 'variabel'))
                i, prev, prev_word = j, 'x', word; continue
            if c == '{':
                depth += 1
            elif c == '}':
                if closing and depth == 0:
                    return i + 1
                depth -= 1
            prev, prev_word = c, ''
            i += 1
        return i

    def template_tx(self, i):
        """Som template(); texten räknas som översatt (bara strängar i ${…}-uttrycken kontrolleras för sig)."""
        return self.template(i)


def scan(src, line0=1):
    lx = Lexer(src, line0)
    lx.code(0)
    return lx


# ---------------------------------------------------------------- kontroller
def check_dict(keys, d, where, fel):
    """keys: [(rad, nyckel)]; d: engelsk ordlista."""
    for rad, k in keys:
        if k not in d:
            fel.append(f'{where} rad {rad}: saknar översättning: {k!r}')
    for k, v in d.items():
        if not isinstance(v, str) or not v.strip():
            fel.append(f'{where}: tom översättning för {k!r}')
            continue
        if sorted(set(re.findall(r'\{\d+\}', k))) != sorted(set(re.findall(r'\{\d+\}', v))):
            fel.append(f'{where}: {{n}} skiljer sig: {k!r} -> {v!r}')
        if '"' in v and '"' not in k:
            fel.append(f'{where}: raka citattecken (") i översättningen av {k!r} – använd “ ”')
        if "'" in v and "'" not in k:
            fel.append(f"{where}: rak apostrof (') i översättningen av {k!r} – använd ’")


def leftovers(lx, where, skip=()):
    ut = []
    for rad, txt, i_tx in lx.strings:
        if i_tx or not txt.strip() or txt in TILLATNA or any(a <= rad <= b for a, b in skip):
            continue
        t = re.sub(r'<[^>]+>|&\w+;|\$\{[^}]*\}', ' ', txt)
        for b in TVASPRAKIGA:
            t = t.replace(b, ' ')
        if SV_ORD.search(t):
            ut.append(f'{where} rad {rad}: svensk text utanför tx(): {txt[:90]!r}')
    return ut


def table_labels(src):
    """Etiketter i tabeller som översätts med txProps(NAMN, 'l' | 1) eller txVals(NAMN)."""
    out, spans = [], []
    for m in re.finditer(r"\btx(Props|Vals)\((\w+)(?:,\s*('?\w+'?))?\)", src):
        kind, name, prop = m.group(1), m.group(2), (m.group(3) or '').strip("'")
        d = re.search(r'\bconst\s+' + name + r'\s*=\s*([\[{])', src)
        if not d:
            continue
        i, depth = d.start(1), 0
        for j in range(i, len(src)):
            if src[j] in '[{':
                depth += 1
            elif src[j] in ']}':
                depth -= 1
                if depth == 0:
                    break
        body = src[i:j + 1]
        line = src.count('\n', 0, i) + 1
        spans.append((line, line + body.count('\n')))
        if kind == 'Props' and prop == '1':
            vals = re.findall(r"\[\s*'[^']*'\s*,\s*'([^']*)'", body)
        elif kind == 'Props':
            vals = re.findall(r'\b' + prop + r"\s*:\s*'([^']*)'", body)
        else:
            vals = re.findall(r":\s*'([^']*)'", body) if body.startswith('{') else re.findall(r"'([^']*)'", body)
        out += [(src.count('\n', 0, i) + 1, v) for v in vals]
    return out, spans


class StaticTexts(html.parser.HTMLParser):
    """Text och title/placeholder/aria-label inne i #shell (sidans fasta HTML)."""
    def __init__(self):
        super().__init__()
        self.depth, self.out = 0, []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if self.depth or a.get('id') == 'shell':
            if tag not in ('input', 'br', 'img', 'path', 'rect', 'circle', 'meta', 'link'):
                self.depth += 1
            for k in ('title', 'placeholder', 'aria-label'):
                if a.get(k) and a[k] not in TVASPRAKIGA:
                    self.out.append((self.getpos()[0], a[k]))

    def handle_startendtag(self, tag, attrs):
        if self.depth:
            for k in ('title', 'placeholder', 'aria-label'):
                if dict(attrs).get(k):
                    self.out.append((self.getpos()[0], dict(attrs)[k]))

    def handle_endtag(self, tag):
        if self.depth and tag not in ('input', 'br', 'img', 'path', 'rect', 'circle'):
            self.depth -= 1

    def handle_data(self, data):
        if self.depth and data.strip():
            self.out.append((self.getpos()[0], ' '.join(data.split())))


def i18n_block(text, script_id):
    m = re.search(r'<script id="' + script_id + r'" type="application/json">(.*?)</script>', text, re.S)
    return json.loads(m.group(1)), text[:m.start()].count('\n') + 1


def function_span(src, name):
    m = re.search(r'\bfunction ' + name + r'\s*\(', src)
    if not m:
        return None
    i = src.index('{', m.end())
    lx = Lexer(src)
    end = lx.code(i + 1, closing=True)
    return src.count('\n', 0, m.start()) + 1, src.count('\n', 0, end) + 1


def check_app(fel, varn):
    text = open(os.path.join(PROJ, 'netatlas.html'), encoding='utf-8').read()
    data, _ = i18n_block(text, 'i18n')
    en, en_m, rx = data.get('en', {}), data.get('en_mobile', {}), data.get('en_rx', [])
    m = re.search(r'<script>\n"use strict";\n', text)
    start = m.end()
    end = text.index('</script>', start)
    src = text[start:end]
    line0 = text.count('\n', 0, start) + 1
    lx = scan(src, line0)
    fel += [f'netatlas.html: {e}' for e in lx.err]
    mob = function_span(src, 'mobileViewer')
    mob = (mob[0] + line0 - 1, mob[1] + line0 - 1) if mob else (0, -1)
    keys_main = [(r, k) for r, k, f in lx.calls if k is not None and not mob[0] <= r <= mob[1]]
    keys_mob = [(r, k) for r, k, f in lx.calls if k is not None and mob[0] <= r <= mob[1]]
    for r, k, f in lx.calls:
        if k is None and f != 'variabel':
            fel.append(f'netatlas.html rad {r}: {f}')
    labels, spans = table_labels(src)
    spans = [(a + line0 - 1, b + line0 - 1) for a, b in spans]
    sp = StaticTexts()
    sp.feed(text[:text.index('<script id="i18n"')])
    static_all = {s for _, s in sp.out}
    static = [(r, s) for r, s in sp.out if SV_ORD.search(s)]
    check_dict(keys_main + [(r + line0 - 1, k) for r, k in labels] + static, en, 'netatlas.html', fel)
    check_dict(keys_mob, en_m, 'netatlas.html (mobilkopian)', fel)
    for pat, rep in rx:
        try:
            re.compile(pat)
        except re.error as e:
            fel.append(f'en_rx: ogiltigt mönster {pat!r}: {e}')
        if '"' in rep:
            fel.append(f'en_rx: raka citattecken i {rep!r}')
    used = {k for _, k in keys_main} | {k for _, k in labels} | static_all
    oanv = [k for k in en if k not in used]
    if oanv:
        varn.append(f'netatlas.html: {len(oanv)} översättningar används inte (t.ex. text från hjälpprogrammet via txs): '
                    + ', '.join(repr(k[:40]) for k in oanv[:8]) + (' …' if len(oanv) > 8 else ''))
    fel += leftovers(lx, 'netatlas.html', spans)
    return len(keys_main) + len(keys_mob), len(en)


def check_login(fel):
    text = open(os.path.join(PROJ, 'server', 'login.html'), encoding='utf-8').read()
    if 'id="i18n"' not in text:
        fel.append('server/login.html: saknar <script id="i18n">')
        return 0
    data, _ = i18n_block(text, 'i18n')
    en = data.get('en', {})
    start = text.index('<script>', text.index('id="i18n"')) + len('<script>')
    src = text[start:text.index('</script>', start)]
    line0 = text.count('\n', 0, start) + 1
    lx = scan(src, line0)
    keys = [(r, k) for r, k, f in lx.calls if k is not None]
    sp = StaticTexts.__new__(StaticTexts)
    html.parser.HTMLParser.__init__(sp)
    sp.depth, sp.out = 1, []
    sp.feed(text[text.index('<body'):text.index('<script')])
    static = [(r, s) for r, s in sp.out if SV_ORD.search(s)]
    check_dict(keys + static, en, 'server/login.html', fel)
    fel += leftovers(lx, 'server/login.html')
    return len(keys) + len(static)


def check_part(path, en_path, mob_path=None):
    """Kontroll av en lös kodbit (t.ex. vid en större ändring): nycklar mot en egen ordlista."""
    src = open(path, encoding='utf-8').read()
    en = json.load(open(en_path, encoding='utf-8'))
    en_m = json.load(open(mob_path, encoding='utf-8')) if mob_path else {}
    lx = scan(src)
    fel = [f'{path}: {e}' for e in lx.err]
    mob = function_span(src, 'mobileViewer') or (0, -1)
    for r, k, f in lx.calls:
        if k is None and f != 'variabel':
            fel.append(f'rad {r}: {f}')
        elif k is None:
            fel.append(f'rad {r}: (info) tx med variabel – kontrollera att nyckeln finns: ' + src.splitlines()[r - 1].strip()[:100])
    check_dict([(r, k) for r, k, f in lx.calls if k is not None and not mob[0] <= r <= mob[1]], en, 'ordlista', fel)
    if mob_path or mob[1] >= mob[0]:
        check_dict([(r, k) for r, k, f in lx.calls if k is not None and mob[0] <= r <= mob[1]], en_m, 'mobilordlista', fel)
    labels, spans = table_labels(src)
    fel += leftovers(lx, 'kvar', spans)
    print('\n'.join(fel) or 'Inga fel.')
    print(f'\n{sum(1 for c in lx.calls if c[1] is not None)} tx-anrop, {len(en)} översättningar, {len(fel)} anmärkningar')
    return 1 if fel else 0


def main():
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass
    if len(sys.argv) >= 3:
        mob = sys.argv[sys.argv.index('--mobile') + 1] if '--mobile' in sys.argv else None
        return check_part(sys.argv[1], sys.argv[2], mob)
    fel, varn = [], []
    n_app, n_en = check_app(fel, varn)
    n_login = check_login(fel)
    for v in varn:
        print('  (info) ' + v)
    for f in fel:
        print('  FEL  ' + f)
    print(f'\n{n_app} texter i appen, {n_en} engelska översättningar, {n_login} texter på inloggningssidan – {len(fel)} FEL')
    return 1 if fel else 0


if __name__ == '__main__':
    sys.exit(main())
