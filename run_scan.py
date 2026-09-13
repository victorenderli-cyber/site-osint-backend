# -*- coding: utf-8 -*-
"""Consulta OSINT única (R$ 49,90) — simples, informativa, 100% passiva.
Uso: python run_scan.py <tipo> <alvo> <email> <payment_id>
Tipos: email | username | dominio. Só usa fontes públicas sem API key.
NUNCA: port scan, brute force, exploit ou acesso não autorizado.
"""
import re
import socket
import subprocess
import sys
from datetime import datetime, timezone

import requests

from send_email import enviar_relatorio

UA = {'User-Agent': 'Mozilla/5.0'}
EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
USERNAME_RE = re.compile(r'^[A-Za-z0-9._-]{3,30}$')
DOMAIN_RE = re.compile(r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$')


def cmd(args, timeout=120):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return (r.stdout or '')[-3000:]
    except Exception as e:
        return f'(ferramenta indisponível: {e})'


def sec(titulo):
    return f'\n{"=" * 60}\n{titulo}\n{"=" * 60}\n'


def scan_email(alvo):
    out = [sec('E-MAIL — verificação em fontes públicas')]
    out.append('holehe (contas vinculadas em serviços públicos):')
    out.append(cmd(['holehe', alvo], timeout=180) or '(sem retorno)')
    import hashlib
    h = hashlib.md5(alvo.strip().lower().encode()).hexdigest()
    try:
        r = requests.get(f'https://www.gravatar.com/avatar/{h}?d=404', timeout=15)
        out.append('Gravatar: ' + ('PERFIL EXISTENTE' if r.status_code == 200 else 'sem perfil público'))
    except Exception as e:
        out.append(f'Gravatar: (indisponível: {e})')
    return '\n'.join(out)


def scan_username(alvo):
    out = [sec('USERNAME — perfis públicos')]
    out.append('maigret (3000+ sites):')
    out.append(cmd(['maigret', alvo, '--timeout', '15'], timeout=300) or '(sem retorno)')
    return '\n'.join(out)


def dns_info(dom):
    out = []
    try:
        out.append('A: ' + ', '.join(sorted({r[4][0] for r in socket.getaddrinfo(dom, 80)})))
    except Exception:
        out.append('A: (não resolveu)')
    for dtype, url in (('MX', f'https://dns.google/resolve?name={dom}&type=MX'),
                       ('TXT', f'https://dns.google/resolve?name={dom}&type=TXT')):
        try:
            d = requests.get(url, timeout=15).json()
            vals = [a.get('data', '') for a in d.get('Answer', [])]
            out.append(f'{dtype}: ' + ('; '.join(vals)[:600] if vals else '(nenhum)'))
        except Exception:
            out.append(f'{dtype}: (indisponível)')
    return '\n'.join(out)


def scan_dominio(alvo):
    out = [sec('DOMÍNIO — superfície pública')]
    out.append('-- DNS --\n' + dns_info(alvo))
    try:
        r = requests.get(f'https://crt.sh/?q=%25.{alvo}&output=json', timeout=30).json()
        nomes = sorted({e.get('name_value', '') for e in r if isinstance(e, dict)})
        out.append(f'-- Certificados (crt.sh): {len(nomes)} nomes --')
        out.append('\n'.join(f'  - {n}' for n in list(nomes)[:50]) or '  (nenhum)')
    except Exception as e:
        out.append(f'crt.sh: (indisponível: {e})')
    try:
        r = requests.get(f'https://urlscan.io/api/v1/search/?q=domain:{alvo}&size=10',
                         headers=UA, timeout=25).json()
        tot = r.get('total', 0)
        out.append(f'-- urlscan.io: {tot} capturas públicas --')
        for x in (r.get('results') or [])[:10]:
            pg = (x.get('page') or {})
            out.append(f"  - {pg.get('url', '')} ({x.get('task', {}).get('time', '')})")
    except Exception:
        out.append('urlscan.io: (indisponível)')
    try:
        r = requests.get(f'https://api.hackertarget.com/reverseiplookup/?q={alvo}', timeout=25, headers=UA)
        txt = r.text.strip()[:800]
        out.append('-- Sites no mesmo IP (reverse IP) --\n' + txt)
    except Exception:
        out.append('reverse IP: (indisponível)')
    try:
        r = requests.get(f'http://web.archive.org/cdx/search/cdx?url={alvo}/*&output=json'
                         f'&filter=statuscode:200&collapse=urlkey&limit=20', timeout=25, headers=UA).json()
        out.append(f'-- Wayback Machine: {max(len(r) - 1, 0)} URLs arquivadas (amostra) --')
        for row in (r[1:11] if len(r) > 1 else []):
            out.append(f'  - {row[2]}')
    except Exception:
        out.append('Wayback: (indisponível)')
    for path in ('robots.txt', 'sitemap.xml'):
        try:
            r = requests.get(f'https://{alvo}/{path}', timeout=15, headers=UA)
            out.append(f'{path}: HTTP {r.status_code} ({len(r.content)} bytes)')
        except Exception:
            out.append(f'{path}: (inacessível)')
    try:
        r = requests.get(f'https://{alvo}/', timeout=20, headers=UA)
        hdrs = {k: v for k, v in r.headers.items()
                if k.lower() in ('server', 'x-powered-by', 'strict-transport-security',
                                 'content-security-policy', 'x-frame-options')}
        out.append('-- Headers relevantes --')
        out.append('\n'.join(f'  {k}: {v}' for k, v in hdrs.items()) or '  (nenhum relevante)')
    except Exception as e:
        out.append(f'homepage: (inacessível: {e})')
    return '\n'.join(out)


def main():
    if len(sys.argv) != 5:
        print('Uso: run_scan.py <tipo> <alvo> <email> <payment_id>', file=sys.stderr)
        return 2
    tipo, alvo, email, payment_id = sys.argv[1], sys.argv[2].strip(), sys.argv[3].strip(), sys.argv[4].strip()
    if tipo == 'email' and not EMAIL_RE.match(alvo):
        return 3
    if tipo == 'username' and not USERNAME_RE.match(alvo):
        return 3
    if tipo == 'dominio' and not DOMAIN_RE.match(alvo):
        return 3
    if not EMAIL_RE.match(email):
        return 3

    corpo = scan_email(alvo) if tipo == 'email' else scan_username(alvo) if tipo == 'username' else scan_dominio(alvo)
    agora = datetime.now(timezone.utc).strftime('%d/%m/%Y %H:%M UTC')
    relatorio = (
        'RELATÓRIO OSINT — CONSULTA ÚNICA (R$ 49,90)\n'
        f'Data: {agora}\nTipo: {tipo}\nAlvo: {alvo}\nPagamento: {payment_id}\n'
        'Metodologia: somente dados públicos, sem acesso não autorizado.\n'
        'Limites: ausência de achado não garante inexistência; aprofunde com assessment contratado.\n'
        + corpo +
        '\n\nPróximos passos sugeridos: assessment completo com contrato (superfície, LGPD, vazamentos).\n'
    )
    enviar_relatorio(email, f'Consulta OSINT única — {alvo}', relatorio)
    print('Relatório enviado para', email)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
