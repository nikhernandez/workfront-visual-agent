#!/usr/bin/env python3
"""Bootstrap Debian/Ubuntu. --audit is read-only; default installs and verifies.
Run as the future Chromium user, or use --browser-user when provisioning as root.
Never use a previous session's fingerprint. Requires outbound HTTPS and apt/pip.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request

TARGETS = ('example.com', 'www.google.com')
PEM = re.compile(rb'-----BEGIN CERTIFICATE-----\s*.*?-----END CERTIFICATE-----', re.S)

def run(args, *, data=None, check=True, env=None, user=None, timeout=180):
    def demote():
        os.initgroups(user.pw_name, user.pw_gid)
        os.setgid(user.pw_gid)
        os.setuid(user.pw_uid)
    p = subprocess.run([str(x) for x in args], input=data, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, env=env, timeout=timeout,
                       preexec_fn=demote if user and os.geteuid() == 0 and user.pw_uid else None)
    if check and p.returncode:
        # Do not print subprocess output: proxies/package indexes may contain credentials.
        raise RuntimeError(f'{Path(str(args[0])).name} failed (exit {p.returncode}); TLS checks were not bypassed')
    return p

def fingerprint(pem):
    der = ssl.PEM_cert_to_DER_cert(pem.decode('ascii'))
    return hashlib.sha256(der).hexdigest().upper()

def browser_uids():
    found = set()
    for p in Path('/proc').glob('[0-9]*/comm'):
        try:
            if p.read_text().strip() in ('chrome', 'chromium', 'chromium-browse', 'chrome-headless'):
                found.add(p.stat().st_uid)
        except (OSError, ProcessLookupError):
            pass
    return found

def identity(name):
    uids = browser_uids()
    if name:
        account, source = pwd.getpwnam(name), 'explicit --browser-user'
    elif len(uids) == 1:
        account, source = pwd.getpwuid(next(iter(uids))), 'running Chromium process'
    elif len(uids) > 1:
        raise RuntimeError('Several Chromium users: specify --browser-user')
    elif os.geteuid() == 0 and os.environ.get('SUDO_USER'):
        account, source = pwd.getpwnam(os.environ['SUDO_USER']), 'SUDO_USER'
    else:
        account, source = pwd.getpwuid(os.getuid()), 'current account; no Chromium process'
    if os.geteuid() not in (0, account.pw_uid):
        raise RuntimeError('Run as the Chromium account, or root with --browser-user')
    return account, source

def nss_location(account, override):
    home = Path(account.pw_dir)
    old = home / '.pki/nssdb'
    new = home / '.local/share/pki/nssdb'
    if override:
        p = Path(override)
        if not p.is_absolute():
            raise RuntimeError('--nss-db must be absolute')
        # Arbitrary NSS directories would not necessarily be read by Chromium.
        if p not in (old, new):
            raise RuntimeError('--nss-db must be a standard Chromium NSS location for this account')
        selected = p
    elif old.exists() and new.exists():
        raise RuntimeError('Both NSS locations exist; confirm the active one with --nss-db')
    else:
        selected = new if new.exists() else old
    for p in [selected, *selected.parents]:
        if p.is_symlink():
            raise RuntimeError('Symlink in NSS path: manual review required')
    return selected

def system_bundle():
    # Use the OS bundle, not SSL_CERT_FILE supplied by a caller.
    for path in ('/etc/ssl/certs/ca-certificates.crt', '/etc/pki/tls/certs/ca-bundle.crt'):
        if Path(path).is_file():
            return Path(path)
    raise RuntimeError('OS CA bundle not found; no certificates will be downloaded')

def chain_for(host, bundle):
    command = ['openssl', 's_client', '-connect', host + ':443', '-servername', host,
               '-verify_hostname', host, '-verify_return_error', '-CAfile', bundle,
               '-no-CApath', '-no-CAstore', '-showcerts']
    proxies = urllib.request.getproxies()
    proxy = None if urllib.request.proxy_bypass(host) else proxies.get('https', proxies.get('all'))
    if proxy:
        parsed = urllib.parse.urlsplit(proxy)
        if parsed.scheme != 'http' or not parsed.hostname or parsed.username or parsed.password:
            raise RuntimeError('This script supports HTTP CONNECT proxies without URL credentials only')
        proxy_host = parsed.hostname
        if ':' in proxy_host:
            proxy_host = '[' + proxy_host + ']'
        command += ['-proxy', proxy_host + ':' + str(parsed.port or 80)]
    response = run(command, data=b'', timeout=45)
    certs = PEM.findall(response.stdout)
    if not certs:
        raise RuntimeError('No TLS chain received for ' + host)
    return certs, bool(proxy)

def discover_root(bundle, directory):
    roots = []
    for i, cert in enumerate(PEM.findall(bundle.read_bytes())):
        path = directory / f'root-{i}.pem'
        path.write_bytes(cert + b'\n')
        desc = run(['openssl', 'x509', '-in', path, '-noout', '-text']).stdout
        names = run(['openssl', 'x509', '-in', path, '-noout', '-subject', '-issuer', '-nameopt', 'RFC2253']).stdout.decode().splitlines()
        if b'CA:TRUE' not in desc or len(names) != 2 or names[0].partition('=')[2] != names[1].partition('=')[2]:
            continue
        valid = run(['openssl', 'verify', '-check_ss_sig', '-CAfile', path,
                     '-no-CApath', '-no-CAstore', path], check=False)
        if valid.returncode == 0:
            roots.append((path, cert, fingerprint(cert)))
    observed = []
    candidates = None
    for host in TARGETS:
        chain, via_proxy = chain_for(host, bundle)
        leaf = directory / (host + '.pem')
        leaf.write_bytes(chain[0] + b'\n')
        intermediates = directory / (host + '-chain.pem')
        intermediates.write_bytes(b'\n'.join(chain[1:]) + b'\n')
        matches = set()
        for path, cert, digest in roots:
            cmd = ['openssl', 'verify', '-purpose', 'sslserver', '-verify_hostname', host,
                   '-CAfile', path, '-no-CApath', '-no-CAstore']
            if len(chain) > 1:
                cmd += ['-untrusted', intermediates]
            if run(cmd + [leaf], check=False).returncode == 0:
                matches.add(digest)
        if not matches:
            raise RuntimeError('No individual system root validates ' + host)
        candidates = matches if candidates is None else candidates & matches
        observed.append({'host': host, 'http_connect_proxy': via_proxy,
                         'leaf_sha256': fingerprint(chain[0]), 'validating_roots_sha256': sorted(matches)})
    if len(candidates) != 1:
        raise RuntimeError('No unique shared root for both sites; no NSS change. Network may use public CAs or different proxies.')
    digest = next(iter(candidates))
    path, cert, _ = next(item for item in roots if item[2] == digest)
    subject = run(['openssl', 'x509', '-in', path, '-noout', '-subject', '-dates']).stdout.decode().strip()
    return cert, digest, subject, observed

def apt_install(packages):
    if not packages:
        return
    if os.geteuid() != 0 or not shutil.which('apt-get'):
        raise RuntimeError('Install these system dependencies as root on Debian/Ubuntu: ' + ' '.join(packages))
    env = dict(os.environ, DEBIAN_FRONTEND='noninteractive')
    run(['apt-get', 'update'], env=env, timeout=600)
    run(['apt-get', 'install', '-y', '--no-install-recommends', *packages], env=env, timeout=900)

def bootstrap(account):
    missing = []
    if not shutil.which('certutil'):
        missing.append('libnss3-tools')
    if not Path('/usr/bin/python3').exists() or run(['/usr/bin/python3', '-c', 'import venv, ensurepip'], check=False).returncode:
        missing += ['python3', 'python3-venv']
    apt_install(missing)
    env = dict(os.environ, HOME=account.pw_dir, USER=account.pw_name, LOGNAME=account.pw_name)
    # Keep Chromium and its NSS database under the same account, even when provisioning as root.
    env.pop('PLAYWRIGHT_BROWSERS_PATH', None)
    env['NODE_EXTRA_CA_CERTS'] = str(system_bundle())
    env['PIP_CERT'] = str(system_bundle())
    env['PIP_CONFIG_FILE'] = '/dev/null'
    env.pop('NODE_TLS_REJECT_UNAUTHORIZED', None)
    env.pop('PYTHONHTTPSVERIFY', None)
    venv = Path(account.pw_dir) / '.local/share/capture-report/venv'
    if venv.is_symlink():
        raise RuntimeError('Unexpected virtualenv symlink')
    if not (venv / 'bin/python').exists():
        run(['/usr/bin/python3', '-m', 'venv', venv], env=env, user=account)
    python = venv / 'bin/python'
    check = run([python, '-c', 'import playwright.sync_api, reportlab, fitz'], check=False, env=env, user=account)
    if check.returncode:
        run([python, '-m', 'pip', '--isolated', 'install', '--cert', system_bundle(), '--index-url', 'https://pypi.org/simple', 'playwright', 'reportlab', 'PyMuPDF'], env=env, user=account, timeout=900)
    # Playwright checks packages and apt installs only missing OS dependencies.
    if os.geteuid() == 0:
        run([python, '-m', 'playwright', 'install-deps', 'chromium'], env=env, timeout=900)
    run([python, '-m', 'playwright', 'install', 'chromium'], env=env, user=account, timeout=900)
    return python, env

def configure_nss(account, db, cert, digest, directory):
    if account.pw_uid in browser_uids():
        raise RuntimeError('Close Chromium for this account and rerun; existing processes are not killed')
    env = dict(os.environ, HOME=account.pw_dir)
    # Back up the entire existing database before any certutil access that might migrate it.
    backup = None
    if db.exists():
        if db.stat().st_uid != account.pw_uid:
            raise RuntimeError('NSS ownership mismatch; refusing recursive ownership changes')
        backup = Path(tempfile.mkdtemp(prefix='nss-before-', dir=str(db.parent)))
        shutil.copytree(db, backup / 'database', symlinks=True)
        if os.geteuid() == 0:
            for p in [backup, *(backup.rglob('*'))]:
                if not p.is_symlink():
                    os.chown(p, account.pw_uid, account.pw_gid)
    else:
        run([sys.executable, '-c', 'from pathlib import Path; import sys; Path(sys.argv[1]).mkdir(parents=True, mode=0o700)', db], env=env, user=account)
    if not (db / 'cert9.db').exists():
        if any(db.iterdir()):
            raise RuntimeError('Nonempty or legacy NSS database: migration must be reviewed manually')
        run(['certutil', '-N', '-d', 'sql:' + str(db), '--empty-password'], env=env, user=account)
    # Content-addressed nickname, never an issuer/subject name used as identity.
    nickname = 'system-verified-sha256-' + digest
    existing = run(['certutil', '-L', '-d', 'sql:' + str(db), '-n', nickname, '-a'], check=False, env=env, user=account)
    if existing.returncode == 0:
        if fingerprint(existing.stdout) != digest:
            raise RuntimeError('NSS nickname collision; refusing to overwrite')
    else:
        # If identical DER already has another nickname, preserve its policy; fail instead of modifying it.
        listing = run(['certutil', '-L', '-d', 'sql:' + str(db)], env=env, user=account).stdout.decode()
        for line in listing.splitlines():
            match = re.match(r'^(.*?)\s+([A-Za-z]*,[A-Za-z]*,[A-Za-z]*)\s*$', line)
            if not match:
                continue
            other = run(['certutil', '-L', '-d', 'sql:' + str(db), '-n', match[1], '-a'], env=env, user=account)
            if fingerprint(other.stdout) == digest:
                if match[2] != 'C,,':
                    raise RuntimeError('This certificate already has another trust policy; preserved unchanged. Review manually.')
                nickname = match[1]
                existing = other
                break
        if existing.returncode != 0:
            # certutil runs as account; pass the PEM via stdin, avoiding root-only temp files.
            run(['certutil', '-A', '-d', 'sql:' + str(db), '-n', nickname, '-t', 'C,,', '-a'], data=cert + b'\n', env=env, user=account)
    exported = run(['certutil', '-L', '-d', 'sql:' + str(db), '-n', nickname, '-a'], env=env, user=account).stdout
    if fingerprint(exported) != digest:
        raise RuntimeError('NSS fingerprint verification failed')
    listing = run(['certutil', '-L', '-d', 'sql:' + str(db)], env=env, user=account).stdout.decode()
    if not any(re.fullmatch(re.escape(nickname) + r'\s+C,,\s*', line) for line in listing.splitlines()):
        raise RuntimeError('NSS trust is not C,,; existing policy was not overwritten')
    return {'nickname': nickname, 'trust': 'C,,', 'exported_sha256': digest,
            'backup': str(backup) if backup else None}

SMOKE = r'''
import json, os, tempfile, urllib.request, urllib.parse
from pathlib import Path
from playwright.sync_api import sync_playwright
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader
import fitz
out = Path('/workspace/outputs')
out.mkdir(parents=True, exist_ok=True)
with sync_playwright() as p:
    proxies = urllib.request.getproxies()
    proxy_url = proxies.get('https', proxies.get('all'))
    launch = {'headless': True, 'chromium_sandbox': os.geteuid() != 0}
    if proxy_url:
        parsed = urllib.parse.urlsplit(proxy_url)
        if parsed.scheme != 'http' or parsed.username or parsed.password:
            raise RuntimeError('Unsupported proxy configuration')
        launch['proxy'] = {'server': proxy_url, 'bypass': proxies.get('no', '')}
    browser = p.chromium.launch(**launch)
    context = browser.new_context(ignore_https_errors=False, viewport={'width':1280,'height':900})
    results = []
    for host in ('example.com','www.google.com'):
        page = context.new_page()
        response = page.goto('https://' + host, wait_until='domcontentloaded', timeout=60000)
        if response is None or response.status >= 400 or not page.url.startswith('https://'):
            raise RuntimeError('HTTPS navigation failed: ' + host)
        results.append({'host':host,'status':response.status,'url':page.url})
        if host == 'example.com':
            png = out / 'comprobacion-example.png'
            page.screenshot(path=str(png))
        page.close()
    context.close()
    browser.close()
pdf = out / 'comprobacion-entorno.pdf'
c = canvas.Canvas(str(pdf), pagesize=(842,595))
c.drawString(36,559,'Comprobacion tecnica: https://example.com')
c.drawImage(ImageReader(str(png)),36,80,width=770,height=450,preserveAspectRatio=True,anchor='c')
c.save()
doc = fitz.open(pdf)
assert len(doc) == 1 and doc[0].get_images() and 'example.com' in doc[0].get_text()
with tempfile.TemporaryDirectory(prefix='pdf-preview-') as tmp:
    preview = Path(tmp) / 'page.png'
    doc[0].get_pixmap().save(preview)
    assert preview.stat().st_size > 1000
print(json.dumps({'https':results,'pdf':str(pdf),'png':str(png),'pdf_images':len(doc[0].get_images()),'visual_review':'Manual inspection required for production reports'}))
'''

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--audit', action='store_true', help='Read-only discovery; does not install, import or launch Chromium')
    parser.add_argument('--browser-user')
    parser.add_argument('--nss-db')
    parser.add_argument('--report', help='Write a JSON audit report')
    args = parser.parse_args()
    if not shutil.which('openssl'):
        if args.audit:
            raise RuntimeError('openssl missing')
        apt_install(['openssl', 'ca-certificates'])
    if not run(['openssl', 'version']).stdout.startswith(b'OpenSSL 3.'):
        raise RuntimeError('OpenSSL 3.x required for isolated trust validation')
    account, source = identity(args.browser_user)
    db = nss_location(account, args.nss_db)
    bundle = system_bundle()
    report = {'timestamp_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'mode':'audit' if args.audit else 'configure', 'browser_user':account.pw_name,
              'uid':account.pw_uid, 'home':account.pw_dir, 'identity_source':source,
              'nss_db':str(db), 'nss_exists':db.exists(), 'system_bundle':str(bundle)}
    with tempfile.TemporaryDirectory(prefix='verify-environment-ca-') as temp:
        cert, digest, description, observations = discover_root(bundle, Path(temp))
        report.update(root_sha256=digest, root_description=description, observations=observations)
        print(json.dumps(report, indent=2), flush=True)
        if not args.audit:
            python, env = bootstrap(account)
            report['nss'] = configure_nss(account, db, cert, digest, Path(temp))
            # A new browser process picks up NSS; no insecure TLS switches are used.
            smoke = run([python, '-c', SMOKE], env=env, user=account, timeout=180)
            report['verification'] = json.loads(smoke.stdout)
            report['python'] = str(python)
    if args.report:
        Path(args.report).write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))

if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, subprocess.TimeoutExpired, OSError, ValueError) as error:
        print('ERROR: ' + str(error), file=sys.stderr)
        sys.exit(1)
