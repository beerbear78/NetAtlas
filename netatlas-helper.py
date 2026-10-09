#!/usr/bin/env python3
"""NetAtlas – lokal hjälptjänst för nätverksskanning.

Startar en webbserver på 127.0.0.1 som visar netatlas.html och erbjuder
ett API för att skanna det lokala nätet (ping, ARP-tabell, portar, värdnamn,
HTTP-titel och Shelly-identifiering). Endast standardbiblioteket används.

    python netatlas-helper.py               # starta och öppna webbläsaren
    python netatlas-helper.py --update-oui  # hämta tillverkarlista (IEEE) först
"""
if __name__ == '__main__':
    print('Startar NetAtlas …', flush=True)  # syns direkt, innan resten laddas
import argparse
import concurrent.futures as cf
import html
import ipaddress
import json
import os
import platform
import re
import secrets
import shutil
import struct
import tempfile
import base64
import hashlib
import hmac
import xml.etree.ElementTree as ET
import socket
import socketserver
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.request
import uuid
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get('NETATLAS_DATA_DIR') or HERE  # i Docker: /data (appdata-mappen)
HTML_FILE = os.path.join(HERE, 'netatlas.html')
if not os.path.exists(HTML_FILE) and os.path.exists(os.path.join(HERE, 'it-inventarie.html')):
    HTML_FILE = os.path.join(HERE, 'it-inventarie.html')  # äldre filnamn
OUI_FILE = os.path.join(DATA_DIR, 'oui.txt')
OUI_URL = 'https://standards-oui.ieee.org/oui/oui.txt'
SYSTEM = 'Windows' if os.name == 'nt' else platform.system()  # platform.system() frågar WMI på Windows och kan dröja länge
WIN = SYSTEM == 'Windows'
NOWINDOW = 0x08000000 if WIN else 0

# Serverläge (Docker): server/app.py sätter STORE till PostgreSQL-lagringen. None = lokalt läge med filer bredvid programmet.
STORE = None
SCAN_CIDRS = [c.strip() for c in os.environ.get('SCAN_CIDRS', '').split(',') if c.strip()]
ALLOWED_HOSTS = {h.strip().lower() for h in os.environ.get('ALLOWED_HOSTS', '').split(',') if h.strip()}
HOST_NET = os.environ.get('NETATLAS_NETWORK', '').lower() == 'host'


def host_ok(host):
    """Skydd mot DNS-rebinding. Lokalt: bara 127.0.0.1/localhost. På servern: ALLOWED_HOSTS (tomt = alla – inloggning krävs ändå)."""
    name = (host or '').rsplit(':', 1)[0].lower()
    if STORE is None:
        return name in ('127.0.0.1', 'localhost')
    return not ALLOWED_HOSTS or name.strip('[]') in ALLOWED_HOSTS


class FastServer(ThreadingHTTPServer):
    """Webbserver som startar direkt: hoppar över namnuppslaget (socket.getfqdn) som kan ta flera sekunder på Windows."""
    allow_reuse_address = not WIN  # på Windows skulle det tillåta två servrar på samma port

    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]

PORTS_QUICK = [80, 443, 22]
PORTS_FULL = [21, 22, 23, 53, 80, 443, 445, 554, 631, 1433, 1880, 1883, 3306, 3389, 5000, 5001, 5432, 6379,
              8006, 8080, 8086, 8123, 8443, 9100, 9443, 27017, 32400]

# (mönster i titel/server/värdnamn/tillverkare, typ, tillverkare)
RULES = [
    (r'fortigate|fortinet', 'firewall', 'Fortinet'),
    (r'pfsense|netgate', 'firewall', 'Netgate pfSense'),
    (r'opnsense', 'firewall', 'OPNsense'),
    (r'sophos', 'firewall', 'Sophos'),
    (r'sonicwall', 'firewall', 'SonicWall'),
    (r'watchguard', 'firewall', 'WatchGuard'),
    (r'unifi|ubiquiti', 'ap', 'Ubiquiti'),
    (r'mikrotik|routeros', 'router', 'MikroTik'),
    (r'synology|diskstation', 'nas', 'Synology'),
    (r'qnap', 'nas', 'QNAP'),
    (r'hikvision', 'camera', 'Hikvision'),
    (r'dahua', 'camera', 'Dahua'),
    (r'reolink', 'camera', 'Reolink'),
    (r'\baxis\b', 'camera', 'Axis'),
    (r'tasmota', 'iot', 'Tasmota'),
    (r'esphome', 'iot', 'ESPHome'),
    (r'home ?assistant', 'homeassistant', 'Home Assistant'),
    (r'unraid', 'unraid', 'Lime Technology Unraid'),
    (r'proxmox', 'proxmox', 'Proxmox'),
    (r'truenas|freenas', 'nas', 'TrueNAS'),
    (r'brother', 'printer', 'Brother'),
    (r'epson', 'printer', 'Epson'),
    (r'canon', 'printer', 'Canon'),
    (r'laserjet|officejet|deskjet', 'printer', 'HP'),
    (r'raspberry', 'server', 'Raspberry Pi'),
    (r'espressif', 'iot', ''),
]

OUI = {}
scan_lock = threading.Lock()


# ---------- hjälpfunktioner ----------
def run(cmd, timeout=5):
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout, creationflags=NOWINDOW)
        return r.returncode, r.stdout.decode('utf-8', 'ignore')
    except (OSError, subprocess.TimeoutExpired):
        return -1, ''


def norm_mac(s):
    if not s:
        return ''
    parts = re.split(r'[:\-.]', s.strip())
    if len(parts) == 1 and len(parts[0]) == 12:
        parts = re.findall('..', parts[0])
    if len(parts) != 6:
        return ''
    return ':'.join(p.zfill(2).upper() for p in parts)


def ping(ip):
    if WIN:
        _, out = run(['ping', '-n', '1', '-w', '600', ip], 3)
        return 'TTL=' in out.upper()
    cmd = ['ping', '-c', '1', '-t', '1', ip] if SYSTEM == 'Darwin' else ['ping', '-c', '1', '-W', '1', ip]
    code, _ = run(cmd, 3)
    return code == 0


def tcp(ip, port, timeout=0.5):
    """'open', 'refused' (värden lever men porten är stängd) eller None."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return 'open'
    except ConnectionRefusedError:
        return 'refused'
    except OSError:
        return None


def arp_table():
    res = {}
    lines = []
    if not WIN and os.path.exists('/proc/net/arp'):
        with open('/proc/net/arp') as f:
            lines = f.read().splitlines()[1:]
    else:
        _, out = run(['arp', '-a'] if WIN else ['arp', '-an'], 8)
        lines = out.splitlines()
    for line in lines:
        m_ip = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', line)
        m_mac = re.search(r'\b([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})\b', line)
        if not (m_ip and m_mac):
            continue
        mac = norm_mac(m_mac.group(1))
        if not mac or mac in ('FF:FF:FF:FF:FF:FF', '00:00:00:00:00:00') or mac.startswith(('01:00:5E', '33:33')):
            continue
        res[m_ip.group(1)] = mac
    return res


def load_oui():
    OUI.clear()
    if not os.path.exists(OUI_FILE):
        return
    with open(OUI_FILE, encoding='utf-8', errors='ignore') as f:
        for line in f:
            m = re.match(r'^\s*([0-9A-F]{2})-([0-9A-F]{2})-([0-9A-F]{2})\s+\(hex\)\s+(.+)$', line)
            if m:
                OUI[''.join(m.group(1, 2, 3))] = m.group(4).strip()


def update_oui():
    req = urllib.request.Request(OUI_URL, headers={'User-Agent': 'Mozilla/5.0 (NetAtlas)'})
    with urllib.request.urlopen(req, timeout=90) as r:
        data = r.read()
    if b'(hex)' not in data:
        raise RuntimeError('Oväntat innehåll i OUI-listan')
    with open(OUI_FILE, 'wb') as f:
        f.write(data)
    load_oui()


def random_mac(mac):
    return bool(mac) and bool(int(mac[:2], 16) & 2)


def oui_vendor(mac):
    if not mac or random_mac(mac):
        return ''
    return OUI.get(mac.replace(':', '')[:6], '')


def rdns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return ''


SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE


def http_get(url, timeout=2.5, limit=65536):
    req = urllib.request.Request(url, headers={'User-Agent': 'NetAtlas-scan'})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=SSL_CTX) as r:
            return r.status, r.headers, r.read(limit)
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read(limit) if e.fp else b''


def shelly(ip):
    try:
        _, _, body = http_get(f'http://{ip}/shelly', 2)
        j = json.loads(body)
    except Exception:
        return None
    if not isinstance(j, dict) or 'mac' not in j or not ('type' in j or 'gen' in j or 'model' in j):
        return None
    return {
        'gen': j.get('gen', 1),
        'model': j.get('model') or j.get('type') or '',
        'app': j.get('app') or '',
        'name': j.get('name') or '',
        'id': j.get('id') or '',
        'mac': norm_mac(j.get('mac', '')),
        'fw': j.get('ver') or j.get('fw') or '',
        'auth': bool(j.get('auth_en', j.get('auth', False))),
    }


def http_info(ip, ports):
    for scheme, port in (('http', 80), ('https', 443), ('http', 8123), ('https', 8006), ('http', 8080), ('https', 8443)):
        if port not in ports:
            continue
        try:
            _, headers, body = http_get(f'{scheme}://{ip}:{port}/')
        except Exception:
            continue
        m = re.search(rb'<title[^>]*>(.*?)</title>', body or b'', re.I | re.S)
        title = html.unescape(m.group(1).decode('utf-8', 'ignore')).strip()[:120] if m else ''
        return {
            'url': f'{scheme}://{ip}' + ('' if port in (80, 443) else f':{port}'),
            'title': re.sub(r'\s+', ' ', title),
            'server': (headers.get('Server') or '')[:80] if headers else '',
        }
    return None


def guess(h):
    g = {'type': '', 'vendor': '', 'model': '', 'fw': '', 'name': ''}
    s = h.get('shelly')
    if s:
        g.update(type='iot', vendor='Shelly', model=' '.join(x for x in (s['app'], s['model']) if x) or 'Shelly',
                 fw=s['fw'], name=s['name'] or s['id'])
        return g
    http = h.get('http') or {}
    text = ' '.join([http.get('title', ''), http.get('server', ''), h.get('hostname', ''), h.get('vendor', '')]).lower()
    for pat, typ, ven in RULES:
        if re.search(pat, text):
            g['type'], g['vendor'] = typ, ven
            break
    ports = h.get('ports', [])
    if not g['type']:
        if 8123 in ports:
            g['type'], g['vendor'] = 'homeassistant', 'Home Assistant'
        elif 8006 in ports:
            g['type'], g['vendor'] = 'proxmox', 'Proxmox'
        elif 9100 in ports or 631 in ports:
            g['type'] = 'printer'
        elif 554 in ports:
            g['type'] = 'camera'
        elif 3389 in ports or 445 in ports:
            g['type'] = 'pc'
    if not g['vendor']:
        g['vendor'] = h.get('vendor', '')
    if h.get('hostname'):
        g['name'] = h['hostname'].split('.')[0]
    return g


def own_ips():
    ips = set()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('192.0.2.1', 9))  # skickar inget, väljer bara utgående gränssnitt
        ips.add(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    try:
        for ai in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ips.add(ai[4][0])
    except OSError:
        pass
    return [ip for ip in ips if ipaddress.ip_address(ip).is_private and not ip.startswith(('127.', '169.254.'))]


def local_cidrs():
    out = []
    for ip in own_ips():
        c = str(ipaddress.ip_network(ip + '/24', strict=False))
        if c not in out:
            out.append(c)
    return out


def own_mac():
    n = uuid.getnode()
    mac = ':'.join(f'{(n >> s) & 0xff:02X}' for s in range(40, -1, -8))
    return '' if random_mac(mac) else mac


# ---------- skanning ----------
def probe(ip, parallel=False):
    """parallel=True vid enstaka uppslag (snabbare); vid hel skanning körs värdarna redan parallellt."""
    def check(ports):
        if parallel:
            with cf.ThreadPoolExecutor(len(ports)) as ex:
                return list(zip(ports, ex.map(lambda p: tcp(ip, p), ports)))
        return [(p, tcp(ip, p)) for p in ports]

    alive = ping(ip)
    ports = []
    for p, st in check(PORTS_QUICK):
        if st == 'open':
            ports.append(p)
        if st is not None:
            alive = True
    if alive:
        ports += [p for p, st in check([p for p in PORTS_FULL if p not in PORTS_QUICK]) if st == 'open']
    return ip, alive, sorted(ports)


def details(ip, ports, arp, mine):
    h = {'ip': ip, 'mac': arp.get(ip, ''), 'ports': ports, 'self': ip in mine}
    if h['self'] and not h['mac']:
        h['mac'] = own_mac()
    with cf.ThreadPoolExecutor(3) as ex:
        f_dns = ex.submit(rdns, ip)
        f_sh = ex.submit(shelly, ip) if 80 in ports else None
        f_http = ex.submit(http_info, ip, ports)
        try:
            h['hostname'] = f_dns.result(timeout=3)
        except Exception:
            h['hostname'] = ''
        h['shelly'] = f_sh.result() if f_sh else None
        h['http'] = f_http.result()
    if h['shelly'] and h['shelly']['mac']:
        h['mac'] = h['mac'] or h['shelly']['mac']
    h['vendor'] = oui_vendor(h['mac'])
    h['randomMac'] = random_mac(h['mac'])
    h['guess'] = guess(h)
    return h


def check_net(text, max_addr=1024):
    net = ipaddress.ip_network(text.strip(), strict=False)
    if net.version != 4 or not net.is_private:
        raise ValueError('Endast privata IPv4-nät (t.ex. 192.168.1.0/24) kan skannas.')
    if net.num_addresses > max_addr:
        raise ValueError('För stort nät – max /22 (1024 adresser).')
    return net


def scan(cidr):
    net = check_net(cidr)
    ips = [str(i) for i in net.hosts()] if net.num_addresses > 2 else [str(i) for i in net]
    t0 = time.time()
    with cf.ThreadPoolExecutor(128) as ex:
        probed = list(ex.map(probe, ips))
    arp = arp_table()
    mine = set(own_ips())
    found = {ip: ports for ip, alive, ports in probed if alive}
    for ip in arp:
        if ipaddress.ip_address(ip) in net and ip not in found:
            found[ip] = []
    for ip in mine:
        if ipaddress.ip_address(ip) in net and ip not in found:
            found[ip] = []
    with cf.ThreadPoolExecutor(48) as ex:
        hosts = list(ex.map(lambda kv: details(kv[0], kv[1], arp, mine), found.items()))
    hosts.sort(key=lambda h: ipaddress.ip_address(h['ip']))
    return {'cidr': str(net), 'took': round(time.time() - t0, 1), 'hosts': hosts}


def host_lookup(ip):
    addr = ipaddress.ip_address(ip.strip())
    check_net(str(addr) + '/32')
    ip, alive, ports = probe(str(addr), parallel=True)
    arp = arp_table()
    mine = set(own_ips())
    if not alive and ip not in arp and ip not in mine:
        return {'ip': ip, 'found': False}
    h = details(ip, ports, arp, mine)
    h['found'] = True
    return h


# ---------- live-status ----------
def ping_many(text):
    ips = []
    for part in (text or '').split(','):
        part = part.strip()
        if not part:
            continue
        addr = ipaddress.ip_address(part)
        if addr.version != 4 or not addr.is_private:
            raise ValueError(f'Ogiltig eller icke-privat adress: {part}')
        ips.append(str(addr))
    if len(ips) > 512:
        raise ValueError('Max 512 adresser per anrop.')

    def check(ip):
        if ping(ip):
            return ip, True
        return ip, any(tcp(ip, p, 0.4) is not None for p in PORTS_QUICK)

    t0 = time.time()
    with cf.ThreadPoolExecutor(64) as ex:
        res = dict(ex.map(check, ips))
    return {'status': res, 'took': round(time.time() - t0, 1)}


# ---------- import av rutiner/jobb ----------
def check_host(host):
    host = (host or '').strip()
    if not host or host.startswith('-'):
        raise ValueError('Ange värd/IP.')
    try:
        ip = socket.gethostbyname(host)
    except OSError:
        raise ValueError(f'Okänd värd: {host}')
    if not ipaddress.ip_address(ip).is_private:
        raise ValueError('Endast lokala/privata adresser tillåts.')
    return ip


def ha_triggers(cfg):
    trig = cfg.get('triggers') or cfg.get('trigger') or []
    if isinstance(trig, dict):
        trig = [trig]
    out = []
    for t in trig:
        if not isinstance(t, dict):
            continue
        p = t.get('trigger') or t.get('platform') or '?'
        ent = t.get('entity_id')
        ent = ', '.join(ent) if isinstance(ent, list) else (ent or '')
        if p == 'time':
            at = t.get('at')
            at = at if isinstance(at, list) else [at]
            out.append('kl ' + ', '.join(re.sub(r'^(\d\d:\d\d):00$', r'\1', str(a)) for a in at if a))
        elif p == 'time_pattern':
            out.append('mönster ' + ' '.join(f'{k[0]}={t[k]}' for k in ('hours', 'minutes', 'seconds') if k in t))
        elif p == 'sun':
            out.append(f"sol: {t.get('event', '')}{' ' + str(t['offset']) if t.get('offset') else ''}")
        elif p == 'state':
            out.append(f"när {ent}" + (f" → {t['to']}" if t.get('to') is not None else ''))
        elif p == 'numeric_state':
            lim = ' '.join(x for x in (f"> {t['above']}" if 'above' in t else '', f"< {t['below']}" if 'below' in t else '') if x)
            out.append(f'när {ent} {lim}'.strip())
        elif p == 'homeassistant':
            out.append(f"vid HA-{t.get('event', '')}")
        elif p == 'event':
            out.append(f"händelse {t.get('event_type', '')}")
        elif p == 'mqtt':
            out.append(f"MQTT {t.get('topic', '')}")
        elif p == 'zone':
            out.append(f"zon {t.get('zone', '')}")
        else:
            out.append(p)
    if len(out) > 3:
        out = out[:3] + [f'+{len(out) - 3}']
    return ' · '.join(out)


def ha_root(base):
    u = urlparse(base if '://' in (base or '') else 'http://' + (base or ''))
    if u.scheme not in ('http', 'https') or not u.hostname:
        raise ValueError('Ogiltig URL till Home Assistant.')
    check_host(u.hostname)
    return f'{u.scheme}://{u.netloc}'


def ha_get(root, token, path):
    if not token:
        raise ValueError('Token saknas.')
    req = urllib.request.Request(root + path, headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=10, context=SSL_CTX) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        if e.code == 401:
            raise ValueError('Home Assistant nekade token (401). Skapa en "Long-lived access token" under din profil i HA.')
        raise ValueError(f'Home Assistant svarade {e.code} på {path}')
    except urllib.error.URLError as e:
        raise ValueError(f'Kunde inte nå Home Assistant på {root}: {e.reason}')


def ha_jobs(base, token):
    root = ha_root(base)
    states = ha_get(root, token, '/api/states')
    items = [x for x in states if str(x.get('entity_id', '')).startswith(('automation.', 'script.'))]

    def cfg(x):
        aid = (x.get('attributes') or {}).get('id')
        if not x['entity_id'].startswith('automation.') or not aid:
            return None
        try:
            return ha_get(root, token, '/api/config/automation/config/' + quote(str(aid), safe=''))
        except Exception:
            return None

    with cf.ThreadPoolExecutor(8) as ex:
        cfgs = list(ex.map(cfg, items))
    jobs = []
    for x, c in zip(items, cfgs):
        a = x.get('attributes') or {}
        auto = x['entity_id'].startswith('automation.')
        jobs.append({
            'extId': x['entity_id'],
            'name': a.get('friendly_name') or x['entity_id'],
            'source': 'homeassistant',
            'kind': 'automation' if auto else 'script',
            'enabled': x.get('state') != 'off' if auto else True,
            'lastRun': a.get('last_triggered') or '',
            'schedule': ha_triggers(c) if c else ('' if auto else 'skript'),
            'command': (c or {}).get('description', '') or x['entity_id'],
        })
    return {'jobs': jobs, 'host': root}


def ha_live(base, token, ents):
    root = ha_root(base)
    states = ha_get(root, token, '/api/states')
    wanted = [e.strip() for e in (ents or '').split(',') if e.strip()][:40]
    items = []
    if wanted:
        by = {x.get('entity_id'): x for x in states}
        for e in wanted:
            x = by.get(e)
            if not x:
                items.append({'k': e, 'v': 'finns inte', 'warn': True})
                continue
            a = x.get('attributes') or {}
            v = x.get('state')
            items.append({'k': a.get('friendly_name') or e, 'v': f"{v} {a.get('unit_of_measurement') or ''}".strip(),
                          'warn': v in ('unavailable', 'unknown')})
    else:
        try:
            items.append({'k': 'Version', 'v': str(ha_get(root, token, '/api/config').get('version', '?'))})
        except Exception:
            pass
        upd = [x for x in states if str(x.get('entity_id', '')).startswith('update.') and x.get('state') == 'on']
        names = ', '.join((x.get('attributes') or {}).get('friendly_name') or x['entity_id'] for x in upd[:4])
        items.append({'k': 'Uppdateringar som väntar', 'v': f"{len(upd)}{': ' + names if upd else ''}{' …' if len(upd) > 4 else ''}", 'warn': bool(upd)})
        unav = [x for x in states if x.get('state') == 'unavailable']
        items.append({'k': 'Otillgängliga entiteter', 'v': str(len(unav)), 'warn': len(unav) > 0})
        items.append({'k': 'Aktiva automationer', 'v': str(sum(1 for x in states if str(x.get('entity_id', '')).startswith('automation.') and x.get('state') == 'on'))})
    return {'items': items}


SSH_SCRIPT = (
    "echo '###HOST'; hostname; uname -sr; "
    "echo '###CRON'; crontab -l 2>/dev/null; "
    "echo '###USNAMES'; for d in /boot/config/plugins/user.scripts/scripts/*/; do "
    "[ -d \"$d\" ] && printf '%s\\t%s\\n' \"$(basename \"$d\")\" \"$(head -c 200 \"$d/name\" 2>/dev/null | tr -d '\\n')\"; done; "
    "echo '###UNRAID'; cat /boot/config/plugins/user.scripts/schedule.json 2>/dev/null; echo; "
    "echo '###TIMERS'; systemctl list-timers --all --no-pager --no-legend 2>/dev/null | head -200; "
    "echo '###END'"
)
INTERPRETERS = {'bash', 'sh', 'php', 'python', 'python3', 'perl', 'cd', 'nice', 'ionice', 'flock', 'timeout', 'sudo', '&&'}
SYSTEM_TIMERS = r'^(systemd-|apt-|man-db|logrotate|fstrim|motd|e2scrub|dpkg|fwupd|snap|phpsessionclean|update-notifier|ua-|sysstat|plocate|mlocate|certbot|anacron)'
CRON_RE = r'^([\d*/,\-]+\s+[\d*/,\-]+\s+[\d*/,\-]+\s+[\w*/,\-]+\s+[\w*/,\-]+)\s+(.+)$'


def cron_name(cmd):
    toks = cmd.split('>')[0].split()
    for tk in toks:
        b = tk.rstrip(';').split('/')[-1]
        if b and b not in INTERPRETERS and not b.startswith('-') and '=' not in b:
            return b[:60]
    return cmd[:60]


def systemd_date(s):
    m = re.search(r'(\d{4}-\d\d-\d\d) (\d\d:\d\d:\d\d)', s or '')
    return f'{m.group(1)}T{m.group(2)}' if m else ''


def parse_ssh(out):
    sec, cur = {}, None
    for line in out.splitlines():
        if line.startswith('###'):
            cur = line[3:].strip()
            sec[cur] = []
        elif cur:
            sec[cur].append(line)
    jobs = []
    for line in sec.get('CRON', []):
        l = line.strip()
        if not l or l.startswith('#') or re.match(r'^\w+=', l):
            continue
        m = re.match(r'^(@\w+)\s+(.+)$', l) or re.match(CRON_RE, l)
        if not m:
            continue
        sched, cmd = m.group(1).strip(), m.group(2).strip()
        jobs.append({'extId': f'cron:{sched} {cmd}'[:300], 'name': cron_name(cmd), 'source': 'cron', 'kind': 'cron',
                     'schedule': sched, 'enabled': True, 'command': cmd})
    names = {}
    for line in sec.get('USNAMES', []):
        if '\t' in line:
            k, v = line.split('\t', 1)
            names[k] = v.strip() or k
    scheduled = set()
    raw = '\n'.join(sec.get('UNRAID', [])).strip()
    if raw:
        try:
            data = json.loads(raw)
        except ValueError:
            data = {}
        for key, v in (data.items() if isinstance(data, dict) else []):
            m = re.search(r'/scripts/([^/]+)/script', key)
            if not m or not isinstance(v, dict):
                continue
            folder = m.group(1)
            scheduled.add(folder)
            freq = v.get('frequency', '') or ''
            sched = v.get('custom', '') if freq == 'custom' else freq
            jobs.append({'extId': 'userscript:' + folder, 'name': names.get(folder, folder), 'source': 'unraid', 'kind': 'userscript',
                         'schedule': sched, 'enabled': freq not in ('', 'disabled'), 'command': key})
    for folder, nm in names.items():
        if folder not in scheduled:
            jobs.append({'extId': 'userscript:' + folder, 'name': nm, 'source': 'unraid', 'kind': 'userscript',
                         'schedule': 'manuellt', 'enabled': False,
                         'command': f'/boot/config/plugins/user.scripts/scripts/{folder}/script'})
    for line in sec.get('TIMERS', []):
        m = re.search(r'(\S+\.timer)\s+(\S+)\s*$', line)
        if not m:
            continue
        unit, act = m.group(1), m.group(2)
        dates = re.findall(r'\d{4}-\d\d-\d\d \d\d:\d\d:\d\d', line)
        nxt, last = ('', '')
        if line.strip().startswith('n/a') or line.strip().startswith('-'):
            last = dates[0] if dates else ''
        else:
            nxt = dates[0] if dates else ''
            last = dates[1] if len(dates) > 1 else ''
        name = unit[:-6]
        jobs.append({'extId': 'timer:' + unit, 'name': name, 'source': 'systemd', 'kind': 'timer', 'schedule': 'systemd-timer',
                     'enabled': True, 'command': act, 'nextRun': systemd_date(nxt), 'lastRun': systemd_date(last),
                     'system': bool(re.match(SYSTEM_TIMERS, name))})
    host = ' / '.join(x.strip() for x in sec.get('HOST', []) if x.strip())
    return {'jobs': jobs, 'host': host}


def ssh_run(host, user, port, script):
    ip = check_host(host)
    user = (user or 'root').strip()
    if not re.match(r'^[A-Za-z0-9._][A-Za-z0-9._-]{0,31}$', user):
        raise ValueError('Ogiltigt användarnamn.')
    port = int(port or 22)
    if not 0 < port < 65536:
        raise ValueError('Ogiltig port.')
    cmd = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8', '-o', 'StrictHostKeyChecking=accept-new',
           '-p', str(port), f'{user}@{ip}', script]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=30, creationflags=NOWINDOW)
    except FileNotFoundError:
        raise ValueError('ssh saknas. Installera "OpenSSH-klient" under Inställningar → System → Valfria funktioner.')
    except subprocess.TimeoutExpired:
        raise ValueError('SSH tog för lång tid (timeout).')
    out = r.stdout.decode('utf-8', 'ignore')
    err = r.stderr.decode('utf-8', 'ignore').strip()
    if '###END' not in out:
        if 'Permission denied' in err or 'publickey' in err:
            raise ValueError('SSH nekades. Kräver inloggning med SSH-nyckel (lösenord stöds inte). '
                             'Kör "ssh-keygen" en gång och lägg in innehållet i ~/.ssh/id_ed25519.pub hos servern '
                             '(Unraid: Users → root → SSH authorized keys).')
        raise ValueError('SSH misslyckades: ' + (err.splitlines()[-1] if err else f'kod {r.returncode}'))
    return out


def ssh_jobs(host, user, port):
    return parse_ssh(ssh_run(host, user, port, SSH_SCRIPT))


LIVE_SCRIPT = (
    "echo '###UP'; cat /proc/uptime; echo '###LOAD'; cat /proc/loadavg; "
    "echo '###MEM'; grep -E 'MemTotal|MemAvailable' /proc/meminfo; "
    "echo '###DF'; df -P / /mnt/user /mnt/cache 2>/dev/null | tail -n +2; "
    "echo '###VAR'; grep -E '^(mdState|mdResyncPos|mdResyncSize|sbSyncErrs)=' /var/local/emhttp/var.ini 2>/dev/null; "
    "echo '###DISKS'; grep -E '^\\[|^(name|temp|status|type)=' /var/local/emhttp/disks.ini 2>/dev/null; "
    "echo '###DOCKER'; if command -v docker >/dev/null 2>&1; then docker ps -q | wc -l; docker ps -aq | wc -l; fi; "
    "echo '###END'"
)


def sections(out):
    sec, cur = {}, None
    for line in out.splitlines():
        if line.startswith('###'):
            cur = line[3:].strip()
            sec[cur] = []
        elif cur:
            sec[cur].append(line.rstrip())
    return sec


def parse_live(out):
    sec, items = sections(out), []
    up = (sec.get('UP') or [''])[0].split()
    if up:
        t = float(up[0])
        d, h, m = int(t // 86400), int(t % 86400 // 3600), int(t % 3600 // 60)
        items.append({'k': 'Upptid', 'v': f'{d} d {h} h' if d else f'{h} h {m} min'})
    ld = (sec.get('LOAD') or [''])[0].split()
    if len(ld) >= 3:
        items.append({'k': 'Last (1/5/15 min)', 'v': ' / '.join(ld[:3])})
    mem = {}
    for l in sec.get('MEM', []):
        mm = re.match(r'(\w+):\s+(\d+)', l)
        if mm:
            mem[mm.group(1)] = int(mm.group(2))
    if mem.get('MemTotal'):
        used = 1 - mem.get('MemAvailable', 0) / mem['MemTotal']
        items.append({'k': 'Minne', 'v': f"{used * 100:.0f} % av {mem['MemTotal'] / 1048576:.1f} GB", 'warn': used > .92})
    seen = set()
    for l in sec.get('DF', []):
        q = l.split()
        if len(q) >= 6 and q[5] not in seen and q[1].isdigit():
            seen.add(q[5])
            pct = int(q[4].rstrip('%') or 0)
            kb = int(q[1])
            size = f'{kb / 1073741824:.1f} TB' if kb >= 1073741824 else f'{kb / 1048576:.0f} GB'
            items.append({'k': f'Disk {q[5]}', 'v': f'{pct} % av {size}', 'warn': pct >= 90})
    var = {}
    for l in sec.get('VAR', []):
        if '=' in l:
            k, v = l.split('=', 1)
            var[k] = v.strip().strip('"')
    if var.get('mdState'):
        items.append({'k': 'Array', 'v': var['mdState'], 'warn': var['mdState'] != 'STARTED'})
        pos, size = int(var.get('mdResyncPos') or 0), int(var.get('mdResyncSize') or 0)
        if pos > 0 and size > 0:
            items.append({'k': 'Paritetskontroll', 'v': f'pågår {pos / size * 100:.1f} %'})
        elif 'sbSyncErrs' in var:
            items.append({'k': 'Paritetsfel (senaste kontroll)', 'v': var['sbSyncErrs'], 'warn': var['sbSyncErrs'] not in ('0', '')})
    disks, cur = [], None
    for l in sec.get('DISKS', []):
        if l.startswith('['):
            cur = {}
            disks.append(cur)
        elif '=' in l and cur is not None:
            k, v = l.split('=', 1)
            cur[k] = v.strip().strip('"')
    disks = [d for d in disks if d.get('status') and d.get('status') != 'DISK_NP' and d.get('type') != 'Flash']
    if disks:
        bad = [d.get('name', '?') for d in disks if d.get('status') != 'DISK_OK']
        temps = [int(d['temp']) for d in disks if (d.get('temp') or '').isdigit()]
        items.append({'k': 'Diskar', 'v': f"{len(disks) - len(bad)} OK" + (f", problem: {', '.join(bad)}" if bad else ''), 'warn': bool(bad)})
        if temps:
            items.append({'k': 'Högsta disktemp', 'v': f'{max(temps)} °C', 'warn': max(temps) >= 50})
    dk = [l.strip() for l in sec.get('DOCKER', []) if l.strip().isdigit()]
    if len(dk) == 2:
        items.append({'k': 'Docker-containrar', 'v': f'{dk[0]} av {dk[1]} körs'})
    return {'items': items}


def ssh_live(host, user, port):
    return parse_live(ssh_run(host, user, port, LIVE_SCRIPT))


# ---------- säkerhetskopior och bifogade filer ----------
BACKUP_DEFAULT = os.path.join(DATA_DIR, 'backups')
FILES_DIR = os.path.join(DATA_DIR, 'data', 'files')
BK_RE = re.compile(r'^netatlas-\d{8}-\d{6}\.json$')
FILE_ID = re.compile(r'^[a-z0-9]{6,32}$')
FILE_RE = re.compile(r'^[a-z0-9]{6,32}\.bin$')


def backup_dir(d):
    # på servern alltid appdata-mappen: webbläsaren ska inte kunna välja godtyckliga mappar på servern
    d = os.path.abspath(os.path.expanduser(d.strip())) if d and d.strip() and STORE is None else BACKUP_DEFAULT
    os.makedirs(d, exist_ok=True)
    return d


def do_backup(d, keep, data):
    if not data or '"ct"' not in data:
        raise ValueError('Ingen krypterad data att spara.')
    d = backup_dir(d)
    keep = max(1, min(365, int(keep or 30)))
    name = time.strftime('netatlas-%Y%m%d-%H%M%S.json')
    with open(os.path.join(d, name), 'w', encoding='utf-8') as f:
        f.write(data)
    files = sorted(x for x in os.listdir(d) if BK_RE.match(x))
    for old in files[:-keep]:
        os.remove(os.path.join(d, old))
    copied = 0
    if STORE is not None:
        copied = STORE.export_files(os.path.join(d, 'files'))
    elif os.path.isdir(FILES_DIR):
        fd = os.path.join(d, 'files')
        os.makedirs(fd, exist_ok=True)
        for x in os.listdir(FILES_DIR):
            if FILE_RE.match(x) and not os.path.exists(os.path.join(fd, x)):
                shutil.copy2(os.path.join(FILES_DIR, x), os.path.join(fd, x))
                copied += 1
    return {'dir': d, 'file': name, 'kept': min(len(files), keep), 'filesCopied': copied}


def list_backups(d):
    d = backup_dir(d)
    out = [{'name': x, 'size': os.path.getsize(os.path.join(d, x)), 'mtime': os.path.getmtime(os.path.join(d, x))}
           for x in os.listdir(d) if BK_RE.match(x)]
    out.sort(key=lambda x: x['name'], reverse=True)
    return {'dir': d, 'backups': out[:50]}


def backup_path(d, name):
    if not BK_RE.match(name or ''):
        raise ValueError('Ogiltigt filnamn.')
    return os.path.join(backup_dir(d), name)


def file_id(i):
    if not FILE_ID.match(i or ''):
        raise ValueError('Ogiltigt fil-id.')
    return i


def file_path(i):
    file_id(i)
    os.makedirs(FILES_DIR, exist_ok=True)
    return os.path.join(FILES_DIR, i + '.bin')


# ---------- molnbackup: S3-kompatibel lagring och WebDAV ----------
def _http(method, url, headers=None, body=None, insecure=False, timeout=60):
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    ctx = SSL_CTX if insecure else ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read() if e.fp else b''
    except urllib.error.URLError as e:
        raise ValueError(f'Kunde inte nå {urlparse(url).netloc}: {e.reason}')


def _cloud_err(code, body, what):
    m = re.search(rb'<Code>([^<]+)</Code>', body or b'')
    detail = m.group(1).decode() if m else ''
    hint = {401: 'inloggningen nekades', 403: 'åtkomst nekad – kontrollera nyckel/behörighet', 404: 'hittades inte – kontrollera bucket/sökväg',
            301: 'fel region/endpoint', 400: 'felaktig begäran'}.get(code, '')
    return ValueError(f'{what}: HTTP {code}{" – " + hint if hint else ""}{" (" + detail + ")" if detail else ""}')


def _q(v):
    return quote(str(v), safe='-_.~')


def sigv4(method, host, path, qs, payload_hash, access, secret, region, now, extra=None):
    """AWS Signature Version 4 – returnerar headers inkl. Authorization."""
    amz_date, day = time.strftime('%Y%m%dT%H%M%SZ', now), time.strftime('%Y%m%d', now)
    hdrs = {'host': host, 'x-amz-content-sha256': payload_hash, 'x-amz-date': amz_date, **(extra or {})}
    signed = ';'.join(sorted(hdrs))
    creq = '\n'.join([method, path, qs, ''.join(f'{k}:{hdrs[k]}\n' for k in sorted(hdrs)), signed, payload_hash])
    scope = f'{day}/{region}/s3/aws4_request'
    sts = '\n'.join(['AWS4-HMAC-SHA256', amz_date, scope, hashlib.sha256(creq.encode()).hexdigest()])
    k = ('AWS4' + secret).encode()
    for part in (day, region, 's3', 'aws4_request'):
        k = hmac.new(k, part.encode(), hashlib.sha256).digest()
    sig = hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()
    hdrs['Authorization'] = f'AWS4-HMAC-SHA256 Credential={access}/{scope}, SignedHeaders={signed}, Signature={sig}'
    return hdrs


def s3_request(cfg, method, key='', query=None, body=b'', ctype=None):
    access, secret = (cfg.get('access') or '').strip(), (cfg.get('secret') or '').strip()
    bucket, region = (cfg.get('bucket') or '').strip(), (cfg.get('region') or '').strip() or 'us-east-1'
    if not (access and secret and bucket):
        raise ValueError('Fyll i bucket, access key och secret key.')
    ep = (cfg.get('endpoint') or '').strip().rstrip('/') or f'https://s3.{region}.amazonaws.com'
    if '://' not in ep:
        ep = 'https://' + ep
    u = urlparse(ep)
    if u.hostname and u.hostname.endswith('amazonaws.com'):
        host, path = f'{bucket}.s3.{region}.amazonaws.com', '/' + '/'.join(_q(x) for x in key.split('/')) if key else '/'
    else:  # path-style för B2, R2, Wasabi, MinIO m.fl.
        host = u.netloc
        path = (u.path.rstrip('/') + '/' + _q(bucket) + ('/' + '/'.join(_q(x) for x in key.split('/')) if key else ''))
    qs = '&'.join(f'{_q(k)}={_q(v)}' for k, v in sorted((query or {}).items()))
    extra = {'content-type': ctype} if ctype else {}
    hdrs = sigv4(method, host, path, qs, hashlib.sha256(body).hexdigest(), access, secret, region, time.gmtime(), extra)
    url = f'{u.scheme}://{host}{path}' + (f'?{qs}' if qs else '')
    return _http(method, url, {k2: v for k2, v in hdrs.items() if k2 != 'host'}, body if method in ('PUT', 'POST') else None, bool(cfg.get('insecure')))


def _prefix(cfg):
    p = (cfg.get('prefix') or 'netatlas').strip().strip('/')
    return p + '/' if p else ''


def _xml_items(body, tag):
    root = ET.fromstring(body)
    for el in root.iter():
        el.tag = el.tag.split('}', 1)[-1]
    return root.iter(tag)


def s3_list(cfg):
    pre = _prefix(cfg)
    code, body = s3_request(cfg, 'GET', '', {'list-type': '2', 'prefix': pre, 'max-keys': '1000'})
    if code != 200:
        raise _cloud_err(code, body, 'Kunde inte lista bucket')
    out = []
    for c in _xml_items(body, 'Contents'):
        key = c.findtext('Key') or ''
        name = key[len(pre):]
        if BK_RE.match(name):
            out.append({'name': name, 'size': int(c.findtext('Size') or 0), 'modified': c.findtext('LastModified') or ''})
    return out


def dav_base(cfg):
    url = (cfg.get('url') or '').strip()
    if not url.startswith(('http://', 'https://')):
        raise ValueError('Ange WebDAV-adressen, t.ex. https://moln.exempel.se/remote.php/dav/files/namn/NetAtlas/')
    return url.rstrip('/') + '/'


def dav_headers(cfg, extra=None):
    tok = base64.b64encode(f"{cfg.get('user', '')}:{cfg.get('pass', '')}".encode()).decode()
    h = {'Authorization': 'Basic ' + tok}
    h.update(extra or {})
    return h


def dav_list(cfg):
    base = dav_base(cfg)
    code, body = _http('PROPFIND', base, dav_headers(cfg, {'Depth': '1', 'Content-Type': 'application/xml'}),
                       b'<?xml version="1.0"?><d:propfind xmlns:d="DAV:"><d:prop><d:getlastmodified/><d:getcontentlength/></d:prop></d:propfind>',
                       bool(cfg.get('insecure')))
    if code == 404:
        return []
    if code not in (200, 207):
        raise _cloud_err(code, body, 'Kunde inte lista WebDAV-mappen')
    out = []
    for r in _xml_items(body, 'response'):
        name = urllib.parse.unquote((r.findtext('href') or '').rstrip('/').rsplit('/', 1)[-1])
        if BK_RE.match(name):
            out.append({'name': name, 'size': int(r.findtext('.//getcontentlength') or 0), 'modified': r.findtext('.//getlastmodified') or ''})
    return out


def cloud_list(cfg):
    t = cfg.get('type')
    lst = s3_list(cfg) if t == 's3' else dav_list(cfg) if t == 'webdav' else None
    if lst is None:
        raise ValueError('Välj typ av molnlagring.')
    return sorted(lst, key=lambda x: x['name'], reverse=True)


def cloud_put(cfg, data, keep):
    if not data or '"ct"' not in data:
        raise ValueError('Ingen krypterad data att ladda upp.')
    name = time.strftime('netatlas-%Y%m%d-%H%M%S.json')
    body = data.encode('utf-8')
    if cfg.get('type') == 's3':
        code, rb = s3_request(cfg, 'PUT', _prefix(cfg) + name, None, body, 'application/json')
        if code not in (200, 201):
            raise _cloud_err(code, rb, 'Uppladdning misslyckades')
    else:
        base = dav_base(cfg)
        _http('MKCOL', base, dav_headers(cfg), None, bool(cfg.get('insecure')))  # finns mappen redan blir det 405 – det är ok
        code, rb = _http('PUT', base + name, dav_headers(cfg, {'Content-Type': 'application/json'}), body, bool(cfg.get('insecure')))
        if code not in (200, 201, 204):
            raise _cloud_err(code, rb, 'Uppladdning misslyckades')
    keep = max(1, min(365, int(keep or 30)))
    removed = 0
    for old in cloud_list(cfg)[keep:]:
        if cloud_delete(cfg, old['name']):
            removed += 1
    return {'file': name, 'removed': removed}


def cloud_get(cfg, name):
    if not BK_RE.match(name or ''):
        raise ValueError('Ogiltigt filnamn.')
    if cfg.get('type') == 's3':
        code, body = s3_request(cfg, 'GET', _prefix(cfg) + name)
    else:
        code, body = _http('GET', dav_base(cfg) + name, dav_headers(cfg), None, bool(cfg.get('insecure')))
    if code != 200:
        raise _cloud_err(code, body, 'Kunde inte hämta kopian')
    return body


def cloud_delete(cfg, name):
    if not BK_RE.match(name or ''):
        return False
    if cfg.get('type') == 's3':
        code, _ = s3_request(cfg, 'DELETE', _prefix(cfg) + name)
    else:
        code, _ = _http('DELETE', dav_base(cfg) + name, dav_headers(cfg), None, bool(cfg.get('insecure')))
    return code in (200, 202, 204)


def sync_folders():
    """Mappar som synkas av Google Drive, OneDrive, Dropbox m.fl. (om de finns)."""
    home = os.path.expanduser('~')
    cands = [('Google Drive', d + ':\\' + sub) for d in 'GHIJ' for sub in ('Min enhet', 'My Drive')]
    cands += [('Google Drive', os.path.join(home, 'Google Drive', sub)) for sub in ('Min enhet', 'My Drive', '')]
    cands += [('Dropbox', os.path.join(home, 'Dropbox')), ('iCloud Drive', os.path.join(home, 'iCloudDrive'))]
    try:
        cands += [(('OneDrive' if x == 'OneDrive' else x.replace('OneDrive - ', 'OneDrive (') + ')' if ' - ' in x else x), os.path.join(home, x))
                  for x in os.listdir(home) if x.startswith('OneDrive')]
    except OSError:
        pass
    out, seen = [], set()
    for label, path in cands:
        if path and os.path.isdir(path) and path.lower() not in seen:
            seen.add(path.lower())
            out.append({'label': label, 'path': os.path.join(path, 'NetAtlas')})
    return out


# ---------- Home Assistant: enheter (via template-API) ----------
HA_DEV_TPL = """{%- set ns = namespace(ids=[], out=[]) -%}
{%- for s in states -%}
{%- set did = device_id(s.entity_id) -%}
{%- if did and did not in ns.ids -%}
{%- set ns.ids = ns.ids + [did] -%}
{%- set ns.out = ns.out + [{'id': did, 'name': ((device_attr(did, 'name_by_user') or device_attr(did, 'name')) or '')|string, 'vendor': (device_attr(did, 'manufacturer') or '')|string, 'model': (device_attr(did, 'model') or '')|string, 'fw': (device_attr(did, 'sw_version') or '')|string, 'area': (area_name(did) or '')|string, 'url': (device_attr(did, 'configuration_url') or '')|string, 'entry': (device_attr(did, 'entry_type') or '')|string, 'conn': (device_attr(did, 'connections') or [])|list, 'domain': s.domain}] -%}
{%- endif -%}
{%- endfor -%}
{{ ns.out | tojson }}"""


def ha_template(root, token, template):
    req = urllib.request.Request(root + '/api/template', data=json.dumps({'template': template}).encode(), method='POST',
                                 headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=30, context=SSL_CTX) as r:
            return r.read().decode('utf-8', 'ignore')
    except urllib.error.HTTPError as e:
        if e.code == 401:
            raise ValueError('Home Assistant nekade token (401). Skapa en "Long-lived access token" under din profil i HA.')
        raise ValueError(f'Home Assistant svarade {e.code}: {(e.read() or b"").decode("utf-8", "ignore")[:200]}')
    except urllib.error.URLError as e:
        raise ValueError(f'Kunde inte nå Home Assistant på {root}: {e.reason}')


def ha_devices(base, token):
    if not token:
        raise ValueError('Token saknas.')
    root = ha_root(base)
    txt = ha_template(root, token, HA_DEV_TPL)
    try:
        items = json.loads(txt)
    except ValueError:
        raise ValueError('Oväntat svar från Home Assistant: ' + txt[:200])
    out = []
    for it in items if isinstance(items, list) else []:
        if (it.get('entry') or '').lower() == 'service':
            continue
        mac = ''
        for c in it.get('conn') or []:
            if isinstance(c, (list, tuple)) and len(c) == 2 and str(c[0]).lower() == 'mac':
                mac = norm_mac(str(c[1]))
                break
        url = it.get('url') or ''
        ip = ''
        try:
            hst = urlparse(url).hostname or ''
            ipaddress.ip_address(hst)
            ip = hst
        except ValueError:
            pass
        out.append({'haId': it.get('id') or '', 'name': it.get('name') or '', 'vendor': it.get('vendor') or '',
                    'model': it.get('model') or '', 'fw': it.get('fw') or '', 'area': it.get('area') or '',
                    'url': url if url.startswith(('http://', 'https://')) else '', 'mac': mac, 'ip': ip,
                    'domain': it.get('domain') or ''})
    out.sort(key=lambda x: ((x['area'] or '~').lower(), x['name'].lower()))
    return {'devices': out, 'host': root}


# ---------- Shelly: status, effekt och uppdateringar ----------
def _shelly_req(ip, path, user, pw, timeout=4):
    url = f'http://{ip}{path}'

    def do(auth=None):
        h = {'User-Agent': 'NetAtlas'}
        if auth:
            h['Authorization'] = auth
        with urllib.request.urlopen(urllib.request.Request(url, headers=h), timeout=timeout) as r:
            return json.loads(r.read() or b'{}')

    try:
        return do()
    except urllib.error.HTTPError as e:
        if e.code != 401:
            raise ValueError(f'Shelly svarade HTTP {e.code}')
        if not pw:
            raise ValueError('Shellyn är lösenordsskyddad – lägg in kontot (admin) på enheten i NetAtlas')
        www = e.headers.get('WWW-Authenticate', '') if e.headers else ''
        if www.lower().startswith('digest'):
            prm = {k: (v1 or v2) for k, v1, v2 in re.findall(r'(\w+)=(?:"([^"]*)"|([^,\s]+))', www)}
            alg = prm.get('algorithm', 'MD5')
            hf = hashlib.sha256 if 'SHA-256' in alg.upper() else hashlib.md5
            H = lambda x: hf(x.encode()).hexdigest()
            u = 'admin'  # Gen2+ använder alltid användaren admin
            ha1, ha2 = H(f"{u}:{prm.get('realm', '')}:{pw}"), H(f'GET:{path}')
            cn, nc = secrets.token_hex(8), '00000001'
            resp = H(f"{ha1}:{prm.get('nonce', '')}:{nc}:{cn}:auth:{ha2}")
            auth = (f'Digest username="{u}", realm="{prm.get("realm", "")}", nonce="{prm.get("nonce", "")}", uri="{path}", '
                    f'algorithm={alg}, response="{resp}", qop=auth, nc={nc}, cnonce="{cn}"')
        else:
            auth = 'Basic ' + base64.b64encode(f'{user or "admin"}:{pw}'.encode()).decode()
        try:
            return do(auth)
        except urllib.error.HTTPError as e2:
            raise ValueError('Fel användarnamn/lösenord för Shellyn' if e2.code == 401 else f'Shelly svarade HTTP {e2.code}')
    except urllib.error.URLError as e:
        raise ValueError(f'Shellyn svarar inte: {e.reason}')
    except (TimeoutError, OSError) as e:
        raise ValueError(f'Shellyn svarar inte: {e}')


def shelly_status(ip, user, pw):
    ip = check_host(ip)
    info = _shelly_req(ip, '/shelly', '', '')
    gen = int(info.get('gen', 1) or 1)
    out = {'gen': gen, 'model': info.get('model') or info.get('type') or '', 'name': info.get('name') or '', 'outputs': [],
           'power': None, 'energy': None, 'temp': None, 'rssi': None, 'uptime': None, 'fw': info.get('ver') or info.get('fw') or '',
           'update': '', 'auth': bool(info.get('auth_en', info.get('auth', False))), 'app': info.get('app') or '',
           'covers': [], 'ambient': None, 'humidity': None, 'battery': None, 'lux': None, 'zigbee': None, 'matter': None}
    if gen >= 2:
        st = _shelly_req(ip, '/rpc/Shelly.GetStatus', 'admin', pw)
        psum, has_p, en, has_e = 0.0, False, 0.0, False
        for k, v in st.items():
            if not isinstance(v, dict):
                continue
            comp = k.split(':')[0]
            if comp in ('switch', 'light', 'plug') and 'output' in v:
                out['outputs'].append(bool(v['output']))
            for pk in ('apower', 'act_power', 'total_act_power'):
                if isinstance(v.get(pk), (int, float)):
                    psum += v[pk]
                    has_p = True
                    break
            ae = v.get('aenergy') or {}
            if isinstance(ae, dict) and isinstance(ae.get('total'), (int, float)):
                en += ae['total']
                has_e = True
            # energimätare (Pro 3EM, EM Gen3/Gen4): totalenergi i Wh ligger i emdata/em1data
            if comp in ('emdata', 'em1data'):
                for ek in ('total_act', 'total_act_energy'):
                    if isinstance(v.get(ek), (int, float)):
                        en += v[ek]
                        has_e = True
                        break
            if comp == 'cover':
                out['covers'].append({'state': v.get('state') or '', 'pos': v.get('current_pos')})
            # sensorer (t.ex. H&T, tillägg): rumstemperatur, luftfuktighet, ljus, batteri
            if comp == 'temperature' and isinstance(v.get('tC'), (int, float)):
                out['ambient'] = v['tC']
            if comp == 'humidity' and isinstance(v.get('rh'), (int, float)):
                out['humidity'] = v['rh']
            if comp == 'illuminance' and isinstance(v.get('lux'), (int, float)):
                out['lux'] = v['lux']
            if comp == 'devicepower' and isinstance((v.get('battery') or {}).get('percent'), (int, float)):
                out['battery'] = v['battery']['percent']
            # Gen4: Zigbee- och Matter-status
            if comp == 'zigbee':
                out['zigbee'] = v.get('network_state')
            if comp == 'matter':
                out['matter'] = v.get('num_fabrics', 0)
            t = (v.get('temperature') or {}).get('tC') if isinstance(v.get('temperature'), dict) else None
            if isinstance(t, (int, float)):
                out['temp'] = t if out['temp'] is None else max(out['temp'], t)
        if has_p:
            out['power'] = round(psum, 1)
        if has_e:
            out['energy'] = round(en / 1000, 2)
        sysd = st.get('sys') or {}
        out['uptime'] = sysd.get('uptime')
        out['rssi'] = (st.get('wifi') or {}).get('rssi')
        out['update'] = (((sysd.get('available_updates') or {}).get('stable')) or {}).get('version', '')
    else:
        st = _shelly_req(ip, '/status', user or 'admin', pw)
        out['outputs'] = [bool(r.get('ison')) for r in (st.get('relays') or []) + (st.get('lights') or []) if isinstance(r, dict)]
        ps = [m.get('power') for m in (st.get('meters') or []) + (st.get('emeters') or []) if isinstance(m, dict) and isinstance(m.get('power'), (int, float))]
        if ps:
            out['power'] = round(sum(ps), 1)
        en = sum(m.get('total') / 60000 for m in st.get('meters') or [] if isinstance(m, dict) and isinstance(m.get('total'), (int, float)))
        en += sum(m.get('total') / 1000 for m in st.get('emeters') or [] if isinstance(m, dict) and isinstance(m.get('total'), (int, float)))
        if en:
            out['energy'] = round(en, 2)
        t = st.get('temperature')
        out['temp'] = t if isinstance(t, (int, float)) else (st.get('tmp') or {}).get('tC')
        out['uptime'] = st.get('uptime')
        out['rssi'] = (st.get('wifi_sta') or {}).get('rssi')
        u = st.get('update') or {}
        if u.get('has_update'):
            out['update'] = u.get('new_version') or 'ny version'
        out['fw'] = u.get('old_version') or out['fw']
    return out


# ---------- snabbåtgärder: Wake-on-LAN, ping, SSH, RDP ----------
def wol(mac):
    mac = norm_mac(mac or '')
    if not mac:
        raise ValueError('MAC-adress saknas eller är ogiltig.')
    pkt = b'\xff' * 6 + bytes.fromhex(mac.replace(':', '')) * 16
    targets = {'255.255.255.255'} | {str(ipaddress.ip_network(ip + '/24', strict=False).broadcast_address) for ip in own_ips()}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as so:
        so.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        for t in targets:
            for port in (9, 7):
                try:
                    so.sendto(pkt, (t, port))
                except OSError:
                    pass
    return {'ok': True, 'sent': sorted(targets)}


def ping_one(ip):
    ip = check_host(ip)
    if WIN:
        _, out = run(['ping', '-n', '1', '-w', '1000', ip], 4)
        ok = 'TTL=' in out.upper()
    else:
        code, out = run(['ping', '-c', '1', '-W', '1', ip], 4)
        ok = code == 0
    m = re.search(r'(?:tid|time)[=<]\s*([\d.,]+)\s*ms', out, re.I)
    ms = float(m.group(1).replace(',', '.')) if (ok and m) else None
    ports = [] if ok else [q for q in PORTS_QUICK if tcp(ip, q, 0.6) == 'open']
    return {'up': ok or bool(ports), 'ms': ms, 'ports': ports, 'ip': ip}


def launch(action, ip, user, port):
    ip = check_host(ip)
    if STORE is not None:
        raise ValueError('Knappen öppnar program på den dator där NetAtlas körs, så den fungerar inte när NetAtlas körs på en server. Starta SSH/RDP från din egen dator.')
    if not WIN:
        raise ValueError('Stöds bara på Windows.')
    if action == 'rdp':
        port = int(port or 3389)
        subprocess.Popen(['mstsc', f'/v:{ip}' + (f':{port}' if port != 3389 else '')])
    elif action == 'ssh':
        user = (user or 'root').strip()
        if not re.match(r'^[A-Za-z0-9._][A-Za-z0-9._-]{0,31}$', user):
            raise ValueError('Ogiltigt användarnamn.')
        args = ['ssh', '-p', str(int(port or 22)), f'{user}@{ip}']
        wt = shutil.which('wt')
        if wt:
            subprocess.Popen([wt, 'new-tab', '--title', f'SSH {user}@{ip}'] + args)
        else:
            subprocess.Popen(['cmd', '/c', 'start', f'SSH {user}@{ip}', 'cmd', '/k'] + args)
    else:
        raise ValueError('Okänd åtgärd.')
    return {'ok': True}


# ---------- kontroll av tjänster och certifikat ----------
def check_one(item):
    t0 = time.time()
    try:
        if item.get('url'):
            url = str(item['url'])
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            req = urllib.request.Request(url, headers={'User-Agent': 'NetAtlas-check'})
            try:
                with urllib.request.urlopen(req, timeout=6, context=SSL_CTX) as r:
                    code = r.status
            except urllib.error.HTTPError as e:
                code = e.code
            return {'up': code < 500, 'code': code, 'ms': round((time.time() - t0) * 1000)}
        host, port = str(item.get('host') or ''), int(item.get('port') or 0)
        if not host or not port:
            return {'up': None}
        st = tcp(host, port, 3)
        return {'up': st == 'open', 'code': None, 'ms': round((time.time() - t0) * 1000),
                'err': '' if st == 'open' else ('porten är stängd' if st == 'refused' else 'svarar inte')}
    except urllib.error.URLError as e:
        return {'up': False, 'err': nice_err(e.reason), 'ms': round((time.time() - t0) * 1000)}
    except Exception as e:
        return {'up': False, 'err': nice_err(e)}


def nice_err(e):
    if isinstance(e, ConnectionRefusedError):
        return 'anslutningen nekades'
    if isinstance(e, (socket.timeout, TimeoutError)):
        return 'svarar inte (timeout)'
    if isinstance(e, ssl.SSLError):
        return 'certifikat-/TLS-fel'
    if isinstance(e, socket.gaierror):
        return 'okänt värdnamn'
    if isinstance(e, OSError) and getattr(e, 'winerror', None) in (10060, 10065, 10051):
        return 'svarar inte'
    return (str(e) or type(e).__name__)[:120]


def check_many(items):
    items = [it for it in (items or []) if isinstance(it, dict)][:200]
    with cf.ThreadPoolExecutor(16) as ex:
        res = list(ex.map(check_one, items))
    return {'results': {str(it.get('id')): r for it, r in zip(items, res)}}


def cert_info(host, port=443):
    host = (host or '').strip()
    if '://' in host:
        u = urlparse(host)
        host, port = u.hostname or '', u.port or (443 if u.scheme == 'https' else port)
    elif host.count(':') == 1:
        host, port = host.split(':')
    port = int(port or 443)
    if not host or host.startswith('-'):
        raise ValueError('Ange värdnamn, t.ex. nas.exempel.se')
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                der = ss.getpeercert(binary_form=True)
    except OSError as e:
        raise ValueError(f'Kunde inte ansluta till {host}:{port} – {e}')
    fd, path = tempfile.mkstemp(suffix='.pem')
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(ssl.DER_cert_to_PEM_cert(der))
        info = ssl._ssl._test_decode_cert(path)
    finally:
        os.remove(path)
    exp = ssl.cert_time_to_seconds(info['notAfter'])
    subj = dict(x[0] for x in info.get('subject', ()) if x)
    iss = dict(x[0] for x in info.get('issuer', ()) if x)
    trusted = True
    try:
        with socket.create_connection((host, port), timeout=8) as sock:
            with ssl.create_default_context().wrap_socket(sock, server_hostname=host):
                pass
    except ssl.SSLError:
        trusted = False
    except OSError:
        pass
    return {'host': host, 'port': port, 'notAfter': time.strftime('%Y-%m-%d', time.gmtime(exp)), 'days': int((exp - time.time()) // 86400),
            'subject': subj.get('commonName', ''), 'issuer': iss.get('organizationName') or iss.get('commonName', ''), 'trusted': trusted}


# ---------- MFA för inloggningen (TOTP + nyckeldel skyddad med Windows DPAPI) ----------
MFA_FILE = os.path.join(DATA_DIR, 'data', 'mfa.json')
mfa_lock = threading.Lock()
mfa_fail = {}


def _dpapi(data, protect):
    import ctypes
    from ctypes import wintypes

    class BLOB(ctypes.Structure):
        _fields_ = [('cbData', wintypes.DWORD), ('pbData', ctypes.POINTER(ctypes.c_char))]
    buf = ctypes.create_string_buffer(data, len(data))
    bin_ = BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    bout = BLOB()
    c32 = ctypes.windll.crypt32
    ok = (c32.CryptProtectData(ctypes.byref(bin_), ctypes.c_wchar_p('NetAtlas'), None, None, None, 0x01, ctypes.byref(bout)) if protect
          else c32.CryptUnprotectData(ctypes.byref(bin_), None, None, None, None, 0x01, ctypes.byref(bout)))
    if not ok:
        raise OSError('Windows DPAPI misslyckades')
    try:
        return ctypes.string_at(bout.pbData, bout.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(ctypes.cast(bout.pbData, ctypes.c_void_p))


def _protect(b):
    if STORE is not None:
        return STORE.seal(b)  # på servern: AES-GCM med nyckel från APP_SECRET
    return ('dpapi:' + base64.b64encode(_dpapi(b, True)).decode()) if WIN else ('plain:' + base64.b64encode(b).decode())


def _unprotect(s):
    kind, _, val = s.partition(':')
    if kind == 'seal':
        return STORE.unseal(s)
    raw = base64.b64decode(val)
    return _dpapi(raw, False) if kind == 'dpapi' else raw


def _mfa_load():
    if STORE is not None:
        try:
            return json.loads(STORE.kv_get('mfa') or '{}')
        except ValueError:
            return {}
    try:
        with open(MFA_FILE, encoding='utf-8') as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _mfa_save(d):
    if STORE is not None:
        return STORE.kv_set('mfa', json.dumps(d))
    os.makedirs(os.path.dirname(MFA_FILE), exist_ok=True)
    tmp = MFA_FILE + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(d, f)
    os.replace(tmp, MFA_FILE)


def totp_at(secret_b32, t, step=30, digits=6):
    key = base64.b32decode(secret_b32 + '=' * (-len(secret_b32) % 8), casefold=True)
    h = hmac.new(key, struct.pack('>Q', int(t // step)), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    return str((struct.unpack('>I', h[o:o + 4])[0] & 0x7FFFFFFF) % 10 ** digits).zfill(digits)


def totp_ok(secret_b32, code):
    code = re.sub(r'\D', '', str(code or ''))
    if len(code) != 6:
        return False
    now = time.time()
    return any(hmac.compare_digest(totp_at(secret_b32, now + 30 * w), code) for w in (-1, 0, 1))


class MfaError(ValueError):
    status = 400


def _mfa_check_locked(d, kid, code):
    e = d.get(kid)
    if not e:
        err = MfaError('MFA-nyckeln för den här datan finns inte på den här datorn. Använd återställningsnyckeln.')
        err.status = 404
        raise err
    now = time.time()
    fails = [t for t in mfa_fail.get(kid, []) if now - t < 300]
    if len(fails) >= 5:
        err = MfaError('För många felaktiga koder – vänta några minuter och försök igen.')
        err.status = 429
        raise err
    if not totp_ok(_unprotect(e['secret']).decode(), code):
        fails.append(now)
        mfa_fail[kid] = fails
        raise MfaError('Fel kod från autentiseringsappen.')
    mfa_fail[kid] = []
    return e


def mfa_setup():
    kid = secrets.token_hex(8)
    secret = base64.b32encode(secrets.token_bytes(20)).decode().rstrip('=')
    key = secrets.token_bytes(32)
    with mfa_lock:
        d = _mfa_load()
        d = {k: v for k, v in d.items() if v.get('active') or time.time() - v.get('created', 0) < 86400}
        d[kid] = {'secret': _protect(secret.encode()), 'key': _protect(key), 'active': False, 'created': time.time()}
        _mfa_save(d)
    label = quote(f'NetAtlas:{socket.gethostname()}')
    rec = base64.b32encode(key).decode().rstrip('=')
    return {'kid': kid, 'secret': secret, 'uri': f'otpauth://totp/{label}?secret={secret}&issuer=NetAtlas&algorithm=SHA1&digits=6&period=30',
            'recovery': '-'.join(rec[i:i + 4] for i in range(0, len(rec), 4))}


def mfa_confirm(kid, code):
    with mfa_lock:
        d = _mfa_load()
        e = _mfa_check_locked(d, kid, code)
        e['active'] = True
        _mfa_save(d)
        return {'key': base64.b64encode(_unprotect(e['key'])).decode()}


def mfa_unlock(kid, code):
    with mfa_lock:
        d = _mfa_load()
        e = _mfa_check_locked(d, kid, code)
        if not e.get('active'):
            raise MfaError('Tvåstegsinloggningen är inte aktiverad.')
        return {'key': base64.b64encode(_unprotect(e['key'])).decode()}


def mfa_verify(kid, code):
    with mfa_lock:
        _mfa_check_locked(_mfa_load(), kid, code)
        return {'ok': True}


def mfa_remove(kid, code):
    with mfa_lock:
        d = _mfa_load()
        _mfa_check_locked(d, kid, code)
        d.pop(kid, None)
        _mfa_save(d)
        return {'ok': True}


# ---------- mobilkopia: dela via WiFi (skrivskyddad, krypterad, tidsbegränsad) ----------
MOBILE = {'srv': None, 'token': None, 'html': b'', 'until': 0, 'timer': None, 'port': 8772,
          'host': os.environ.get('NETATLAS_MOBILE_HOST', '0.0.0.0')}


class MobileHandler(BaseHTTPRequestHandler):
    server_version = 'NetAtlas'

    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        tok = MOBILE.get('token')
        if tok and self.path.split('?')[0] == f'/m/{tok}' and time.time() < MOBILE['until']:
            body = MOBILE['html']
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.send_header('X-Frame-Options', 'DENY')
            self.send_header('X-Robots-Tag', 'noindex')
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.send_header('Content-Length', '9')
            self.end_headers()
            self.wfile.write(b'Not found')


def primary_ip():
    try:
        so = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        so.connect(('192.0.2.1', 9))
        ip = so.getsockname()[0]
        so.close()
        return ip
    except OSError:
        return ''


def mobile_stop():
    srv = MOBILE.get('srv')
    if MOBILE.get('timer'):
        MOBILE['timer'].cancel()
    MOBILE.update(srv=None, token=None, html=b'', until=0, timer=None)
    if srv:
        srv.shutdown()      # väntar tills servertråden har stannat, så att porten är fri direkt
        srv.server_close()
    return {'ok': True}


def mobile_share(html, minutes):
    if not html or '<html' not in html[:300]:
        raise ValueError('Ingen mobilkopia att dela.')
    minutes = max(1, min(60, int(minutes or 15)))
    if STORE is not None and not HOST_NET:
        raise ValueError('Delning till mobilen kräver att containern körs med host-nätverk (docker-compose.host.yml). '
                         'Du kan också öppna NetAtlas direkt i mobilens webbläsare.')
    mobile_stop()

    try:
        srv = FastServer((MOBILE['host'], MOBILE['port']), MobileHandler)
    except OSError as e:
        raise ValueError(f'Kunde inte starta delningen på port {MOBILE["port"]}: {e}')
    token = secrets.token_urlsafe(18)
    MOBILE.update(srv=srv, token=token, html=html.encode('utf-8'), until=time.time() + minutes * 60)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    t = threading.Timer(minutes * 60, mobile_stop)
    t.daemon = True
    t.start()
    MOBILE['timer'] = t
    prim = primary_ip()
    ips = sorted(own_ips(), key=lambda x: (x != prim, x))
    return {'urls': [f'http://{ip}:{MOBILE["port"]}/m/{token}' for ip in ips], 'minutes': minutes, 'until': MOBILE['until'] * 1000}


def mobile_save(html, d):
    if not html or '<html' not in html[:300]:
        raise ValueError('Ingen mobilkopia att spara.')
    path = os.path.join(backup_dir(d), 'netatlas-mobil.html')
    with open(path, 'w', encoding='utf-8') as f:
        f.write(html)
    return {'path': path}


# ---------- webbserver ----------
class Handler(BaseHTTPRequestHandler):
    server_version = 'itinv'

    def log_message(self, fmt, *args):
        pass

    def send(self, code, body, ctype):
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.end_headers()
        self.wfile.write(body)

    def json(self, code, obj):
        self.send(code, json.dumps(obj, ensure_ascii=False).encode('utf-8'), 'application/json; charset=utf-8')

    def do_GET(self):
        # skydd mot DNS-rebinding: bara lokala värdnamn (på servern: ALLOWED_HOSTS)
        if not host_ok(self.headers.get('Host')):
            return self.send(403, b'Forbidden', 'text/plain')
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path in ('/', '/netatlas.html', '/it-inventarie.html'):
            try:
                with open(HTML_FILE, 'rb') as f:
                    return self.send(200, f.read(), 'text/html; charset=utf-8')
            except OSError:
                return self.send(404, 'netatlas.html saknas bredvid netatlas-helper.py'.encode('utf-8'), 'text/plain; charset=utf-8')
        if not u.path.startswith('/api/'):
            return self.send(404, b'Not found', 'text/plain')
        # anpassad header => andra webbplatser kan inte anropa API:t (kräver CORS-preflight som vi aldrig godkänner)
        if self.headers.get('X-ITInv') != '1':
            return self.send(403, b'Forbidden', 'text/plain')
        try:
            if u.path == '/api/info':
                return self.json(200, {'version': 2, 'cidrs': SCAN_CIDRS or local_cidrs(), 'oui': len(OUI), 'host': socket.gethostname(),
                                       'backupDefault': BACKUP_DEFAULT, 'filesDir': FILES_DIR,
                                       'syncFolders': [] if STORE is not None else sync_folders(),
                                       'storage': 'server' if STORE is not None else 'local', 'hostNet': HOST_NET})
            if u.path == '/api/vault' and STORE is not None:
                return self.json(200, STORE.vault_get())
            if u.path == '/api/scan':
                if not scan_lock.acquire(blocking=False):
                    return self.json(409, {'error': 'En skanning pågår redan.'})
                try:
                    return self.json(200, scan(q.get('cidr', [''])[0]))
                finally:
                    scan_lock.release()
            if u.path == '/api/host':
                return self.json(200, host_lookup(q.get('ip', [''])[0]))
            if u.path == '/api/ping':
                return self.json(200, ping_many(q.get('ips', [''])[0]))
            if u.path == '/api/import/ha':
                return self.json(200, ha_jobs(self.headers.get('X-Target-Url', ''), self.headers.get('X-Target-Token', '')))
            if u.path == '/api/import/ssh':
                return self.json(200, ssh_jobs(q.get('host', [''])[0], q.get('user', ['root'])[0], q.get('port', ['22'])[0]))
            if u.path == '/api/ha/devices':
                return self.json(200, ha_devices(self.headers.get('X-Target-Url', ''), self.headers.get('X-Target-Token', '')))
            if u.path == '/api/live/ha':
                return self.json(200, ha_live(self.headers.get('X-Target-Url', ''), self.headers.get('X-Target-Token', ''), self.headers.get('X-Entities', '')))
            if u.path == '/api/live/ssh':
                return self.json(200, ssh_live(q.get('host', [''])[0], q.get('user', ['root'])[0], q.get('port', ['22'])[0]))
            if u.path == '/api/backups':
                return self.json(200, list_backups(q.get('dir', [''])[0]))
            if u.path == '/api/backup-get':
                with open(backup_path(q.get('dir', [''])[0], q.get('name', [''])[0]), 'rb') as f:
                    return self.send(200, f.read(), 'application/json; charset=utf-8')
            if u.path == '/api/file' and STORE is not None:
                data = STORE.file_get(file_id(q.get('id', [''])[0]))
                if data is None:
                    return self.json(404, {'error': 'Filen finns inte (borttagen eller flyttad?).'})
                return self.send(200, data, 'application/json; charset=utf-8')
            if u.path == '/api/file-del' and STORE is not None:
                STORE.file_delete(file_id(q.get('id', [''])[0]))
                return self.json(200, {'ok': True})
            if u.path == '/api/file':
                fp = file_path(q.get('id', [''])[0])
                if not os.path.exists(fp):
                    return self.json(404, {'error': 'Filen finns inte (borttagen eller flyttad?).'})
                with open(fp, 'rb') as f:
                    return self.send(200, f.read(), 'application/json; charset=utf-8')
            if u.path == '/api/file-del':
                fp = file_path(q.get('id', [''])[0])
                if os.path.exists(fp):
                    os.remove(fp)
                return self.json(200, {'ok': True})
            if u.path == '/api/update-oui':
                update_oui()
                return self.json(200, {'oui': len(OUI)})
            return self.json(404, {'error': 'Okänd funktion'})
        except ValueError as e:
            return self.json(400, {'error': str(e)})
        except Exception as e:
            return self.json(500, {'error': f'{type(e).__name__}: {e}'})


    def do_POST(self):
        if not host_ok(self.headers.get('Host')) or self.headers.get('X-ITInv') != '1':
            return self.send(403, b'Forbidden', 'text/plain')
        u = urlparse(self.path)
        q = parse_qs(u.query)
        n = int(self.headers.get('Content-Length') or 0)
        if n > 80 * 1024 * 1024:
            return self.json(413, {'error': 'För stor fil (max ca 50 MB).'})
        body = self.rfile.read(n)
        try:
            if u.path == '/api/backup':
                j = json.loads(body or b'{}')
                return self.json(200, do_backup(j.get('dir', ''), j.get('keep', 30), j.get('data', '')))
            if u.path.startswith('/api/') and u.path not in ('/api/backup', '/api/file', '/api/cloud'):
                j = json.loads(body or b'{}')
                if u.path == '/api/vault' and STORE is not None:
                    try:
                        return self.json(200, {'version': STORE.vault_put(int(j.get('version') or 0), j.get('data') or '')})
                    except STORE.Conflict as e:
                        return self.json(409, {'error': 'Datan har ändrats från ett annat fönster eller en annan enhet.', 'conflict': True, 'version': e.version})
                if u.path == '/api/vault/hint' and STORE is not None:
                    STORE.kv_set('hint', str(j.get('hint') or '').strip()[:200])
                    return self.json(200, {'ok': True})
                if u.path == '/api/vault/delete' and STORE is not None:
                    STORE.vault_delete()
                    return self.json(200, {'ok': True})
                if u.path == '/api/shelly':
                    return self.json(200, shelly_status(j.get('ip', ''), j.get('user', ''), j.get('pass', '')))
                if u.path == '/api/action':
                    a = j.get('action')
                    if a == 'wol':
                        return self.json(200, wol(j.get('mac', '')))
                    if a == 'ping':
                        return self.json(200, ping_one(j.get('ip', '')))
                    return self.json(200, launch(a, j.get('ip', ''), j.get('user', ''), j.get('port')))
                if u.path == '/api/check':
                    return self.json(200, check_many(j.get('items')))
                if u.path == '/api/cert':
                    return self.json(200, cert_info(j.get('host', ''), j.get('port', 443)))
                if u.path == '/api/mfa/setup':
                    return self.json(200, mfa_setup())
                if u.path == '/api/mfa/confirm':
                    return self.json(200, mfa_confirm(j.get('kid', ''), j.get('code', '')))
                if u.path == '/api/mfa/unlock':
                    return self.json(200, mfa_unlock(j.get('kid', ''), j.get('code', '')))
                if u.path == '/api/mfa/verify':
                    return self.json(200, mfa_verify(j.get('kid', ''), j.get('code', '')))
                if u.path == '/api/mfa/remove':
                    return self.json(200, mfa_remove(j.get('kid', ''), j.get('code', '')))
                if u.path == '/api/mobile/share':
                    return self.json(200, mobile_share(j.get('html', ''), j.get('minutes', 15)))
                if u.path == '/api/mobile/stop':
                    return self.json(200, mobile_stop())
                if u.path == '/api/mobile/save':
                    return self.json(200, mobile_save(j.get('html', ''), j.get('dir', '')))
                return self.json(404, {'error': 'Okänd funktion'})
            if u.path == '/api/cloud':
                j = json.loads(body or b'{}')
                cfg, act = j.get('cfg') or {}, j.get('action')
                if act == 'test':
                    return self.json(200, {'ok': True, 'count': len(cloud_list(cfg))})
                if act == 'list':
                    return self.json(200, {'backups': cloud_list(cfg)[:50]})
                if act == 'put':
                    return self.json(200, cloud_put(cfg, j.get('data', ''), j.get('keep', 30)))
                if act == 'get':
                    return self.send(200, cloud_get(cfg, j.get('name', '')), 'application/json; charset=utf-8')
                return self.json(400, {'error': 'Okänd åtgärd'})
            if u.path == '/api/file' and STORE is not None:
                STORE.file_put(file_id(q.get('id', [''])[0]), body)
                return self.json(200, {'ok': True, 'size': len(body)})
            if u.path == '/api/file':
                with open(file_path(q.get('id', [''])[0]), 'wb') as f:
                    f.write(body)
                return self.json(200, {'ok': True, 'size': len(body)})
            return self.json(404, {'error': 'Okänd funktion'})
        except MfaError as e:
            return self.json(e.status, {'error': str(e), 'mfa': True})
        except ValueError as e:
            return self.json(400, {'error': str(e)})
        except OSError as e:
            return self.json(500, {'error': f'Kunde inte skriva: {e}'})
        except Exception as e:
            return self.json(500, {'error': f'{type(e).__name__}: {e}'})


def main():
    ap = argparse.ArgumentParser(description='NetAtlas – IT-inventarie med nätverksskanning')
    ap.add_argument('--port', type=int, default=8770)
    ap.add_argument('--no-browser', action='store_true')
    ap.add_argument('--update-oui', action='store_true', help='hämta tillverkarlistan från IEEE')
    a = ap.parse_args()
    load_oui()
    if a.update_oui:
        print('Hämtar tillverkarlista från IEEE …')
        update_oui()
        print(f'{len(OUI)} tillverkare inlästa.')
    url = f'http://127.0.0.1:{a.port}/'
    MOBILE['port'] = a.port + 2

    try:
        srv = FastServer(('127.0.0.1', a.port), Handler)
    except OSError:
        print(f'NetAtlas körs redan på {url} – öppnar webbläsaren.')
        if not a.no_browser:
            webbrowser.open(url)
        time.sleep(3)
        return
    print(f'NetAtlas körs på {url}')
    print(f'Lokala nät: {", ".join(local_cidrs()) or "okänt"} · tillverkarlista: {len(OUI) or "saknas"}')
    print('Låt det här fönstret vara öppet medan du använder NetAtlas. Stäng det (eller tryck Ctrl+C) för att avsluta.')
    if not a.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
