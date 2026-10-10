"""Test av migreringsskript, administrationskommandon, compose-filer och strip_plans.

    python tests/test_server_misc.py

Körs lokalt utan Docker (SQLite i stället för PostgreSQL). Compose-testerna kräver PyYAML (hoppas annars över)."""
import io
import json
import os
import shutil
import sys
import tempfile
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import server_harness as hs  # noqa: E402  (sätter miljö + SQLite)
from server import cli, migrate  # noqa: E402

PROJ = hs.PROJ
ok = fail = 0


def check(name, cond, extra=''):
    global ok, fail
    ok, fail = (ok + 1, fail) if cond else (ok, fail + 1)
    print(f"  {'OK ' if cond else 'FEL'}  {name} {'' if cond else extra}")


def run(mod, *args):
    out = io.StringIO()
    sys.argv = [mod.__name__, *args]
    code = 0
    try:
        with redirect_stdout(out):
            mod.main()
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else (1 if e.code else 0)
        if not isinstance(e.code, int) and e.code:
            out.write(str(e.code))
    return code, out.getvalue()


# ---- migrering ----
imp = os.path.join(os.environ['NETATLAS_DATA_DIR'], 'import')
os.makedirs(os.path.join(imp, 'files'), exist_ok=True)
code, out = run(migrate)
check('utan fil: tydligt fel', code != 0 and 'Hittade ingen' in out, out)
vault = {'app': 'netatlas', 'v': 1, 'salt': 'AA', 'iv': 'BB', 'ct': 'CC'}
old = os.path.join(imp, 'netatlas-20261009-120000.json')
with open(old, 'w', encoding='utf-8') as f:
    json.dump({**vault, 'mfa': {'kid': 'x'}}, f)
os.utime(old, (1e9, 1e9))
code, out = run(migrate)
check('kopia med tvåsteg nekas', code != 0 and 'tvåstegsinloggning' in out, out)
with open(os.path.join(imp, 'netatlas-20261009-130000.json'), 'w', encoding='utf-8') as f:
    json.dump(vault, f)
for i, fid in enumerate(('abc123', 'def456xyz')):
    with open(os.path.join(imp, 'files', fid + '.bin'), 'wb') as f:
        f.write(b'x' * (100 + i))
with open(os.path.join(imp, 'files', 'ogiltig namn.bin'), 'wb') as f:
    f.write(b'y')
code, out = run(migrate, '--hint', 'min ledtråd')
check('migrering lyckas', code == 0 and 'Klart' in out and '2 st' in out, out)
st = hs.sa.STORE
v = st.vault_get()
check('valv + ledtråd i databasen', v['version'] == 1 and json.loads(v['data'])['ct'] == 'CC' and v['hint'] == 'min ledtråd', v)
check('bilagor i databasen', st.file_get('abc123') == b'x' * 100 and st.file_get('def456xyz') == b'x' * 101)
code, out = run(migrate)
check('andra gången utan --force nekas', code != 0 and '--force' in out, out)
code, out = run(migrate, '--force')
check('--force ersätter', code == 0 and st.vault_get()['version'] == 2, out)

# ---- administration ----
code, out = run(cli, 'status')
check('cli status', code == 0 and 'version 2' in out and 'Bifogade filer: 2' in out, out)
st.kv_set('login_totp', st.seal(b'ABCDEF'))
code, out = run(cli, 'reset-2fa')
check('cli reset-2fa', code == 0 and st.kv_get('login_totp') is None, out)
code, out = run(cli, 'okänt')
check('cli okänt kommando visar hjälp', code != 0 and 'reset-2fa' in out, out)

# ---- compose-filer ----
try:
    import yaml
except ImportError:
    yaml = None
    print('  (PyYAML saknas – compose-testerna hoppas över)')
if yaml:
    class Loader(yaml.SafeLoader):
        pass

    Loader.add_multi_constructor('!', lambda ld, suffix, node: ld.construct_sequence(node) if isinstance(node, yaml.SequenceNode) else None)
    c1 = yaml.load(open(os.path.join(PROJ, 'docker-compose.yml'), encoding='utf-8'), Loader=Loader)
    c2 = yaml.load(open(os.path.join(PROJ, 'docker-compose.host.yml'), encoding='utf-8'), Loader=Loader)
    app, db = c1['services']['app'], c1['services']['db']
    text = json.dumps(c1, ensure_ascii=False)
    check('compose: två tjänster', set(c1['services']) == {'app', 'db'})
    check('compose: db utan publicerad port', 'ports' not in db)
    check('compose: depends_on service_healthy', app['depends_on']['db']['condition'] == 'service_healthy')
    check('compose: restart unless-stopped', app['restart'] == db['restart'] == 'unless-stopped')
    check('compose: hälsokontroller', 'healthcheck' in app and 'pg_isready' in str(db['healthcheck']['test']))
    check('compose: inga hårdkodade lösenord', 'POSTGRES_PASSWORD:?' in text and 'APP_PASSWORD:?' in text)
    check('host-override: host-nät + db bara lokalt', c2['services']['app']['network_mode'] == 'host'
          and c2['services']['db']['ports'][0].startswith('127.0.0.1:'))
    c3 = yaml.load(open(os.path.join(PROJ, 'docker-compose.build.yml'), encoding='utf-8'), Loader=Loader)
    check('compose: färdig image från ghcr.io (ingen build)', app['image'].startswith('ghcr.io/beerbear78/netatlas:') and 'build' not in app, app.get('image'))
    check('build-override: bygger från källkoden', c3['services']['app'].get('build') == '.')
    env_example = open(os.path.join(PROJ, '.env.example'), encoding='utf-8').read()
    check('.env.example har alla variabler som compose använder', all(v in env_example for v in (
        'APP_PASSWORD', 'APP_SECRET', 'POSTGRES_PASSWORD', 'NETATLAS_TAG', 'APPDATA', 'PORT', 'LOGIN_2FA')))

# ---- licens och installationsskript ----
check('MIT-licens finns', 'MIT License' in open(os.path.join(PROJ, 'LICENSE'), encoding='utf-8').read())
inst = open(os.path.join(PROJ, 'install.sh'), encoding='utf-8').read()
check('install.sh körs via main() (säkert med curl | bash)', inst.rstrip().endswith('main "$@"'))
check('install.sh visar aldrig lösenordet', 'read -r -s' in inst and 'echo "$NETATLAS_PASSWORD' not in inst)
check('install.sh lägger in stacken i Compose Manager (host-läget som override, .env via envpath)',
      'compose.manager/projects' in inst and 'docker-compose.override.yml' in inst and 'envpath' in inst)
if yaml:
    icon = app['labels'].get('net.unraid.docker.icon', '')
    check('compose: Unraid-ikonen finns i repot', icon.endswith('/main/assets/netatlas-icon.png')
          and os.path.isfile(os.path.join(PROJ, 'assets', 'netatlas-icon.png')), icon)

# ---- strip_plans (idempotent på en kopia) ----
tmp = os.path.join(tempfile.mkdtemp(prefix='netatlas-strip-'), 'netatlas.html')
with open(os.path.join(PROJ, 'netatlas.html'), encoding='utf-8') as f:
    src = f.read()
with open(tmp, 'w', encoding='utf-8', newline='\n') as f:
    f.write(src.replace('</body>', '<script id="housePlans" type="application/json">[{"name":"x"}]</script>\n</body>', 1))
sys.argv = ['strip_plans.py', tmp]
with redirect_stdout(io.StringIO()):
    exec(open(os.path.join(PROJ, 'server', 'strip_plans.py'), encoding='utf-8').read(), {'__name__': '__main__'})
txt = open(tmp, encoding='utf-8').read()
check('strip_plans tar bort inbäddade planer', 'id="housePlans"' not in txt and '</html>' in txt)
check('repots netatlas.html saknar personliga planer', 'id="housePlans"' not in src)
shutil.rmtree(os.path.dirname(tmp), ignore_errors=True)

print(f'\n{ok} OK, {fail} FEL')
shutil.rmtree(hs.TMP, ignore_errors=True)
sys.exit(1 if fail else 0)
