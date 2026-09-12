"""Backend da automação OSINT (AbacatePay Pix + Mercado Pago + scan passivo + e-mail).

Fluxo principal (AbacatePay, recomendado):
1. Site chama POST /api/criar-pix {email, tipo, alvo} → backend cria Pix
   transparente de R$ 49,90 com metadata e devolve QR code.
2. Cliente paga no app do banco. AbacatePay chama POST /webhook/abacatepay
   (evento transparent.completed) com assinatura HMAC.
3. Backend valida a assinatura, lê a metadata e roda run_scan.py,
   enviando o relatório por e-mail. Tudo sem intervenção manual.

Fluxo alternativo (Mercado Pago): POST /api/confirmar, como antes.

Rodar local: pip install -r requirements.txt && python app.py
Deploy grátis sugerido: Render.com (Web Service, plano free) com as envs do .env.example.
"""
import base64
import hashlib
import hmac
import os
import re
import subprocess
from flask import Flask, request, jsonify

import requests

app = Flask(__name__)

MP_ACCESS_TOKEN = os.environ.get('MP_ACCESS_TOKEN', '')
REPORT_FROM = os.environ.get('REPORT_FROM', '')
ABACATEPAY_API_KEY = os.environ.get('ABACATEPAY_API_KEY', '')
ABACATEPAY_WEBHOOK_SECRET = os.environ.get('ABACATEPAY_WEBHOOK_SECRET', '')
ABACATEPAY_BASE = 'https://api.abacatepay.com/v2'
PRECO_CONSULTA_CENTAVOS = 4990  # R$ 49,90

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


@app.get('/api/status')
def status():
    return jsonify(ok=True, mp_configurado=bool(MP_ACCESS_TOKEN),
                   abacatepay_configurado=bool(ABACATEPAY_API_KEY))


def validar_alvo(tipo, alvo):
    if tipo == 'email':
        return bool(EMAIL_RE.match(alvo))
    if tipo == 'username':
        return bool(USERNAME_RE.match(alvo))
    if tipo == 'dominio':
        return bool(DOMAIN_RE.match(alvo))
    return False


ABACATEPAY_PRODUCT_ID = os.environ.get('ABACATEPAY_PRODUCT_ID', '')


@app.post('/api/criar-pix')
def criar_pix():
    """Cria checkout Pix de R$ 49,90 com metadata (email/tipo/alvo)."""
    dados = request.get_json(force=True, silent=True) or {}
    email = (dados.get('email') or '').strip()
    tipo = (dados.get('tipo') or '').strip()
    alvo = (dados.get('alvo') or '').strip()
    if not EMAIL_RE.match(email):
        return jsonify(ok=False, erro='E-mail inválido'), 400
    if not validar_alvo(tipo, alvo):
        return jsonify(ok=False, erro='Alvo inválido para o tipo'), 400
    if not (ABACATEPAY_API_KEY and ABACATEPAY_PRODUCT_ID):
        return jsonify(ok=False, erro='Pix automático não configurado'), 503
    r = requests.post(
        f'{ABACATEPAY_BASE}/checkouts/create',
        headers={'Authorization': f'Bearer {ABACATEPAY_API_KEY}'},
        json={'items': [{'id': ABACATEPAY_PRODUCT_ID, 'quantity': 1}],
              'methods': ['PIX'],
              'metadata': {'email': email, 'tipo': tipo, 'alvo': alvo}},
        timeout=20,
    )
    if r.status_code != 200:
        return jsonify(ok=False, erro='Falha ao gerar Pix'), 502
    data = (r.json().get('data') or {})
    return jsonify(ok=True, id=data.get('id'), url=data.get('url'))


@app.post('/webhook/abacatepay')
def webhook_abacatepay():
    """Recebe transparent.completed, valida HMAC e dispara scan + e-mail."""
    raw = request.get_data()
    assinatura = request.headers.get('X-Webhook-Signature', '')
    if ABACATEPAY_WEBHOOK_SECRET:
        esperado = base64.b64encode(
            hmac.new(ABACATEPAY_WEBHOOK_SECRET.encode(), raw, hashlib.sha256).digest()
        ).decode()
        if not hmac.compare_digest(assinatura, esperado):
            return jsonify(ok=False), 401
    evento = request.get_json(force=True, silent=True) or {}
    if evento.get('event') not in ('checkout.completed', 'transparent.completed'):
        return jsonify(ok=True, ignorado=True)
    data = evento.get('data') or {}
    meta = data.get('metadata') or {}
    email, tipo, alvo = meta.get('email', ''), meta.get('tipo', ''), meta.get('alvo', '')
    if not (EMAIL_RE.match(email) and validar_alvo(tipo, alvo)):
        return jsonify(ok=False, erro='metadata inválida'), 400
    proc = subprocess.run(
        ['python', 'run_scan.py', tipo, alvo, email, str(data.get('id', ''))],
        capture_output=True, text=True, timeout=600,
    )
    if proc.returncode != 0:
        return jsonify(ok=False, erro='Falha ao gerar relatório',
                       log=(proc.stderr or '')[-800:]), 500
    return jsonify(ok=True)


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
