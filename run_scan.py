"""Scan OSINT 100% passivo para a consulta única (R$ 49,90).
Uso: python run_scan.py <tipo> <alvo> <email_cliente> <payment_id>
Tipos: email | username | dominio. Gera relatório TXT e envia por e-mail.
NUNCA faz port scan, brute force, exploit ou acesso não autorizado.
"""
import re
import subprocess
import sys
from datetime import datetime, timezone

from send_email import enviar_relatorio

EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
USERNAME_RE = re.compile(r'^[A-Za-z0-9._-]{3,30}$')
DOMAIN_RE = re.compile(r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$')


def cmd(args, timeout=120):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return (r.stdout or '')[-4000:]
    except Exception as e:
        return f'(ferramenta indisponível: {e})'


def scan_email(alvo):
    return (
        '== Verificação de e-mail (fontes públicas) ==\n'
        f'holehe:\n{cmd(["holehe", alvo])}\n'
    )


def scan_username(alvo):
    return (
        '== Perfis por username (fontes públicas) ==\n'
        f'maigret:\n{cmd(["maigret", alvo, "--timeout", "15"], timeout=300)}\n'
    )


def scan_dominio(alvo):
    import requests as rq
    try:
        r = rq.get(f'https://crt.sh/?q=%25.{alvo}&output=json', timeout=30)
        nomes = sorted({e.get('name_value', '') for e in r.json() if isinstance(e, dict)} or {'(nenhum)'})
        crt = '\n'.join(f'  - {n}' for n in list(nomes)[:60])
    except Exception as e:
        crt = f'(crt.sh indisponível: {e})'
    return (
        '== Domínio (certificados públicos crt.sh) ==\n'
        f'{crt}\n'
        f'subfinder (se instalado):\n{cmd(["subfinder", "-silent", "-d", alvo])}\n'
        f'theHarvester (se instalado):\n{cmd(["theHarvester", "-d", alvo, "-b", "crtsh"], timeout=180)}\n'
    )


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
    agora = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
    relatorio = (
        f'RELATÓRIO OSINT — CONSULTA ÚNICA\nData: {agora}\nTipo: {tipo}\nAlvo: {alvo}\nPagamento MP: {payment_id}\n'
        'Metodologia: somente dados públicos, sem acesso não autorizado.\n\n' + corpo +
        '\nLimites: verificação em fontes públicas; ausência de achado não garante inexistência.\n'
    )
    enviar_relatorio(email, f'Consulta OSINT única — {alvo}', relatorio)
    print('Relatório enviado para', email)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
