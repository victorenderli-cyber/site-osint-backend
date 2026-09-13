"""Backend da automação OSINT (Hotmart + scan passivo + e-mail).

Fluxo principal (Hotmart):
1. Site chama POST /api/iniciar {email, tipo, alvo} → registra pedido
   pendente e devolve o checkout Hotmart com e-mail pré-preenchido.
2. Cliente paga. Hotmart chama POST /webhook/hotmart?hottok=... no evento
   de compra aprovada.
3. Backend cruza o e-mail do comprador, roda run_scan.py e envia o
   relatório por e-mail. Tudo sem intervenção manual.

Fluxo alternativo (Mercado Pago manual): POST /api/confirmar, como antes.

Rodar local: pip install -r requirements.txt && python app.py
Deploy grátis sugerido: Render.com (Web Service, plano free) com as envs do .env.example.
"""
import json
import os
import re
import subprocess
from flask import Flask, request, jsonify

import requests

app = Flask(__name__)

MP_ACCESS_TOKEN = os.environ.get('MP_ACCESS_TOKEN', '')
HOTMART_HOTTOK = os.environ.get('HOTMART_HOTTOK', '')
HOTMART_CHECKOUT_URL = os.environ.get('HOTMART_CHECKOUT_URL', '')
PENDING_FILE = os.environ.get('PENDING_FILE', '/tmp/osint_pending.json')
SITE_URL = os.environ.get('SITE_URL', 'https://victorenderli-cyber.github.io/site-osint/')
CODES_FILE = os.environ.get('CODES_FILE', '/tmp/osint_codes.json')
REPORT_FROM = os.environ.get('REPORT_FROM', '')

EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
USERNAME_RE = re.compile(r'^[A-Za-z0-9._-]{3,30}$')
DOMAIN_RE = re.compile(r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$')


def verificar_pagamento_mp(payment_id):
    """Consulta o status real do pagamento na API do Mercado Pago."""
    if not MP_ACCESS_TOKEN:
        return False, 'MP_ACCESS_TOKEN não configurado no servidor'
    if not re.fullmatch(r'\d+', str(payment_id or '')):
        return False, 'payment_id inválido'
    r = requests.get(
        f'https://api.mercadopago.com/v1/payments/{payment_id}',
        headers={'Authorization': f'Bearer {MP_ACCESS_TOKEN}'},
        timeout=20,
    )
    if r.status_code != 200:
        return False, f'Mercado Pago retornou {r.status_code}'
    status = r.json().get('status')
    return (status == 'approved', f'status={status}')


@app.get('/health')
def health():
    return jsonify(ok=True)


@app.get('/api/status')
def status():
    return jsonify(ok=True, mp_configurado=bool(MP_ACCESS_TOKEN),
                   hotmart_configurado=bool(HOTMART_HOTTOK and HOTMART_CHECKOUT_URL))


def _load_pending():
    try:
        with open(PENDING_FILE, encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}


def _save_pending(d):
    try:
        with open(PENDING_FILE, 'w', encoding='utf-8') as f:
            json.dump(d, f)
    except Exception:
        pass


def _load_codes():
    try:
        with open(CODES_FILE, encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}


def _save_codes(d):
    try:
        with open(CODES_FILE, 'w', encoding='utf-8') as f:
            json.dump(d, f)
    except Exception:
        pass


def _rodar_scan_async(tipo, alvo, email, ref):
    import threading

    def _job():
        subprocess.run(['python', 'run_scan.py', tipo, alvo, email, ref],
                       capture_output=True, text=True, timeout=600)
    threading.Thread(target=_job, daemon=True).start()


@app.post('/api/resgatar')
def resgatar():
    """Troca código único (recebido por e-mail após a compra) por um scan."""
    dados = request.get_json(force=True, silent=True) or {}
    email = (dados.get('email') or '').strip().lower()
    codigo = (dados.get('codigo') or '').strip()
    tipo = (dados.get('tipo') or '').strip()
    alvo = (dados.get('alvo') or '').strip()
    if not EMAIL_RE.match(email):
        return jsonify(ok=False, erro='E-mail inválido'), 400
    if not validar_alvo(tipo, alvo):
        return jsonify(ok=False, erro='Alvo inválido para o tipo'), 400
    codes = _load_codes()
    reg = codes.get(codigo)
    if not reg or reg.get('email') != email:
        return jsonify(ok=False, erro='Código inválido para este e-mail'), 400
    if reg.get('usado'):
        return jsonify(ok=False, erro='Código já utilizado'), 400
    reg['usado'] = True
    _save_codes(codes)
    _rodar_scan_async(tipo, alvo, email, reg.get('ref', 'hotmart'))
    return jsonify(ok=True, msg='Código válido! O relatório chega por e-mail em instantes.')


@app.post('/api/iniciar')
def iniciar():
    """Registra pedido pendente e devolve o checkout Hotmart com e-mail pré-preenchido."""
    import urllib.parse
    dados = request.get_json(force=True, silent=True) or {}
    email = (dados.get('email') or '').strip().lower()
    tipo = (dados.get('tipo') or '').strip()
    alvo = (dados.get('alvo') or '').strip()
    if not EMAIL_RE.match(email):
        return jsonify(ok=False, erro='E-mail inválido'), 400
    if not validar_alvo(tipo, alvo):
        return jsonify(ok=False, erro='Alvo inválido para o tipo'), 400
    if not HOTMART_CHECKOUT_URL:
        return jsonify(ok=False, erro='Checkout não configurado'), 503
    pend = _load_pending()
    pend[email] = {'tipo': tipo, 'alvo': alvo}
    _save_pending(pend)
    sep = '&' if '?' in HOTMART_CHECKOUT_URL else '?'
    url = f'{HOTMART_CHECKOUT_URL}{sep}email={urllib.parse.quote(email)}'
    return jsonify(ok=True, url=url)


@app.post('/webhook/hotmart')
def webhook_hotmart():
    """Hotmart: valida hottok, cruza e-mail com pedido pendente e dispara scan + e-mail."""
    if HOTMART_HOTTOK and request.args.get('hottok') != HOTMART_HOTTOK:
        return jsonify(ok=False), 401
    evento = request.get_json(force=True, silent=True) or request.form.to_dict() or {}
    nome_evento = str(evento.get('event', '')).upper()
    if 'APPROVED' not in nome_evento and 'COMPLETE' not in nome_evento and 'PAID' not in nome_evento:
        return jsonify(ok=True, ignorado=True)
    data = evento.get('data') or {}
    comprador = data.get('buyer') or {}
    email = str(comprador.get('email', '')).strip().lower()
    if not EMAIL_RE.match(email):
        return jsonify(ok=False, erro='e-mail do comprador inválido'), 400
    import secrets as _secrets
    codigo = _secrets.token_urlsafe(9)
    codes = _load_codes()
    codes[codigo] = {'email': email, 'usado': False,
                     'ref': str((data.get('purchase') or {}).get('transaction', 'hotmart'))}
    _save_codes(codes)
    from send_email import enviar_relatorio as _enviar
    try:
        _enviar(email, 'Sua consulta OSINT — código de acesso',
                f'Obrigado pela compra!\n\nSeu código único: {codigo}\n\n'
                 f'Acesse {SITE_URL} e informe este código + o alvo '
                 f'(e-mail, username ou domínio) para receber o relatório.\n'
                 f'Cada código vale 1 consulta.')
    except Exception as e:  # noqa: BLE001
        return jsonify(ok=False, erro=f'compra ok, mas e-mail falhou: {e}'), 500
    return jsonify(ok=True)


def validar_alvo(tipo, alvo):
    if tipo == 'email':
        return bool(EMAIL_RE.match(alvo))
    if tipo == 'username':
        return bool(USERNAME_RE.match(alvo))
    if tipo == 'dominio':
        return bool(DOMAIN_RE.match(alvo))
    return False


@app.post('/api/confirmar')
def confirmar():
    dados = request.get_json(force=True, silent=True) or {}
    email = (dados.get('email') or '').strip()
    tipo = (dados.get('tipo') or '').strip()  # email | username | dominio
    alvo = (dados.get('alvo') or '').strip()
    payment_id = (dados.get('payment_id') or '').strip()

    if not EMAIL_RE.match(email):
        return jsonify(ok=False, erro='E-mail inválido'), 400
    if tipo == 'email' and not EMAIL_RE.match(alvo):
        return jsonify(ok=False, erro='Alvo (e-mail) inválido'), 400
    if tipo == 'username' and not USERNAME_RE.match(alvo):
        return jsonify(ok=False, erro='Alvo (username) inválido'), 400
    if tipo == 'dominio' and not DOMAIN_RE.match(alvo):
        return jsonify(ok=False, erro='Alvo (domínio) inválido'), 400
    if tipo not in ('email', 'username', 'dominio'):
        return jsonify(ok=False, erro='Tipo inválido'), 400

    pago, detalhe = verificar_pagamento_mp(payment_id)
    if not pago:
        return jsonify(ok=False, erro=f'Pagamento não aprovado ({detalhe})'), 402

    proc = subprocess.run(
        ['python', 'run_scan.py', tipo, alvo, email, str(payment_id)],
        capture_output=True, text=True, timeout=600,
    )
    if proc.returncode != 0:
        return jsonify(ok=False, erro='Falha ao gerar relatório', log=proc.stderr[-500:]), 500
    return jsonify(ok=True, msg='Pagamento confirmado. Relatório enviado por e-mail.')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
