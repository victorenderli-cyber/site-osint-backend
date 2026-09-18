"""Backend da automação OSINT (Hotmart + scan passivo + e-mail).

Fluxo principal (Hotmart):
1. Site chama POST /api/iniciar {email, tipo, alvo} → registra pedido
   pendente e devolve o checkout Hotmart com e-mail pré-preenchido.
2. Cliente paga. Hotmart chama POST /webhook/hotmart?hottok=... no evento
   de compra aprovada.
3. Backend cruza o e-mail do comprador, roda run_scan.py e envia o
   relatório por e-mail. Tudo sem intervenção manual.

Fluxo alternativo (Mercado Pago manual): POST /api/confirmar, como antes.

Fluxo Asaas (Pix R$ 199,90):
1. Site chama POST /api/iniciar-asaas {email, tipo, alvo} → cria customer
   + cobrança Pix e devolve invoiceUrl. Sem API key, usa ASAAS_PAYMENT_LINK.
2. Asaas chama POST /webhook/asaas nos eventos PAYMENT_RECEIVED/CONFIRMED.
3. Backend gera o código único e envia por e-mail (mesmo fluxo Hotmart).

Rodar local: pip install -r requirements.txt && python app.py
Deploy grátis sugerido: Render.com (Web Service, plano free) com as envs do .env.example.
"""
import json
import os
import re
import subprocess
import sys
from flask import Flask, request, jsonify

import requests

app = Flask(__name__)

SITE_ORIGIN = os.environ.get('SITE_ORIGIN', 'https://osint-protege.onrender.com')


@app.after_request
def _cors(resp):
    resp.headers['Access-Control-Allow-Origin'] = SITE_ORIGIN
    resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    resp.headers['Access-Control-Allow-Headers'] = 'Content-Type, X-Admin-Token'
    return resp

MP_ACCESS_TOKEN = os.environ.get('MP_ACCESS_TOKEN', '')
HOTMART_HOTTOK = os.environ.get('HOTMART_HOTTOK', '')
HOTMART_CHECKOUT_URL = os.environ.get('HOTMART_CHECKOUT_URL', '')
ASAAS_API_KEY = os.environ.get('ASAAS_API_KEY', '')
ASAAS_ENV = os.environ.get('ASAAS_ENV', 'prod')  # prod | sandbox
ASAAS_PAYMENT_LINK = os.environ.get('ASAAS_PAYMENT_LINK', '')
ASAAS_WEBHOOK_TOKEN = os.environ.get('ASAAS_WEBHOOK_TOKEN', '')
ASAAS_PRICE = float(os.environ.get('ASAAS_PRICE', '199.90'))
PENDING_FILE = os.environ.get('PENDING_FILE', '/tmp/osint_pending.json')
SITE_URL = os.environ.get('SITE_URL', 'https://osint-protege.onrender.com/')
CODES_FILE = os.environ.get('CODES_FILE', '/tmp/osint_codes.json')
REPORT_FROM = os.environ.get('REPORT_FROM', '')
ADMIN_TOKEN = os.environ.get('ADMIN_TOKEN', '')
ORDERS_LOG = os.environ.get('ORDERS_LOG', '/tmp/osint_pedidos.jsonl')

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
                   hotmart_configurado=bool(HOTMART_HOTTOK and HOTMART_CHECKOUT_URL),
                   asaas_configurado=bool(ASAAS_API_KEY or ASAAS_PAYMENT_LINK))


def _asaas_base():
    return ('https://api.asaas.com/v3' if ASAAS_ENV == 'prod'
            else 'https://sandbox.asaas.com/api/v3')


def _asaas_headers():
    return {'access_token': ASAAS_API_KEY, 'Content-Type': 'application/json'}


def _asaas_customer(email):
    """Localiza ou cria o customer Asaas pelo e-mail. Retorna (id, erro)."""
    try:
        r = requests.get(f'{_asaas_base()}/customers', params={'email': email},
                         headers=_asaas_headers(), timeout=20)
        if r.status_code != 200:
            return None, f'Asaas customers retornou {r.status_code}'
        for c in (r.json().get('data') or []):
            if str(c.get('email', '')).lower() == email:
                return c.get('id'), None
        nome = email.split('@')[0].replace('.', ' ').title()
        r = requests.post(f'{_asaas_base()}/customers',
                          json={'name': nome, 'email': email},
                          headers=_asaas_headers(), timeout=20)
        if r.status_code not in (200, 201):
            return None, f'Asaas criar customer retornou {r.status_code}'
        return r.json().get('id'), None
    except Exception as e:
        return None, str(e)


@app.post('/api/iniciar-asaas')
def iniciar_asaas():
    """Cria cobrança Pix de R$ 199,90 na Asaas e devolve o link de pagamento."""
    import datetime
    dados = request.get_json(force=True, silent=True) or {}
    email = (dados.get('email') or '').strip().lower()
    tipo = (dados.get('tipo') or '').strip()
    alvo = (dados.get('alvo') or '').strip()
    if not EMAIL_RE.match(email):
        return jsonify(ok=False, erro='E-mail inválido'), 400
    if not validar_alvo(tipo, alvo):
        return jsonify(ok=False, erro='Alvo inválido para o tipo'), 400
    if not ASAAS_API_KEY:
        if ASAAS_PAYMENT_LINK:
            return jsonify(ok=True, url=ASAAS_PAYMENT_LINK, modo='link-fixo')
        return jsonify(ok=False, erro='Asaas não configurado'), 503
    cust_id, erro = _asaas_customer(email)
    if not cust_id:
        return jsonify(ok=False, erro=f'Asaas: {erro}'), 502
    venc = (datetime.date.today() + datetime.timedelta(days=1)).isoformat()
    r = requests.post(f'{_asaas_base()}/payments', json={
        'customer': cust_id, 'billingType': 'PIX', 'value': ASAAS_PRICE,
        'dueDate': venc, 'description': f'Consulta OSINT única ({tipo})',
        'externalReference': f'{email}|{tipo}|{alvo}'[:120],
    }, headers=_asaas_headers(), timeout=20)
    if r.status_code not in (200, 201):
        return jsonify(ok=False, erro=f'Asaas payments retornou {r.status_code}'), 502
    pj = r.json()
    pend = _load_pending()
    pend[email] = {'tipo': tipo, 'alvo': alvo, 'asaas_id': pj.get('id')}
    _save_pending(pend)
    _log_pedido('cobranca_asaas', email=email, asaas_id=pj.get('id'))
    return jsonify(ok=True, url=pj.get('invoiceUrl'), pagamento=pj.get('id'))


def _asaas_token_ok():
    if not ASAAS_WEBHOOK_TOKEN:
        return True
    got = (request.args.get('token') or request.headers.get('X-Webhook-Token')
           or request.headers.get('asaas-access-token') or '')
    import hmac
    return hmac.compare_digest(got, ASAAS_WEBHOOK_TOKEN)


@app.post('/webhook/asaas')
def webhook_asaas():
    """Asaas: PAYMENT_RECEIVED/CONFIRMED → gera código + envia e-mail."""
    if not _asaas_token_ok():
        return jsonify(ok=False), 401
    evento = request.get_json(force=True, silent=True) or {}
    if str(evento.get('event', '')).upper() not in (
            'PAYMENT_RECEIVED', 'PAYMENT_CONFIRMED', 'PAYMENT_CREDIT_CARD_CAPTURED'):
        return jsonify(ok=True, ignorado=True)
    pay = evento.get('payment') or {}
    email = ''
    ref = str(pay.get('externalReference') or '')
    if '|' in ref:
        email = ref.split('|')[0].strip().lower()
    if not EMAIL_RE.match(email):
        cust_id = pay.get('customer')
        if cust_id and ASAAS_API_KEY:
            try:
                r = requests.get(f'{_asaas_base()}/customers/{cust_id}',
                                 headers=_asaas_headers(), timeout=20)
                if r.status_code == 200:
                    email = str(r.json().get('email', '')).strip().lower()
            except Exception:
                pass
    if not EMAIL_RE.match(email):
        return jsonify(ok=False, erro='e-mail do pagador inválido'), 400
    import secrets as _secrets
    codigo = _secrets.token_urlsafe(9)
    codes = _load_codes()
    codes[codigo] = {'email': email, 'usado': False,
                     'ref': str(pay.get('id', 'asaas'))}
    _save_codes(codes)
    _log_pedido('compra_aprovada', email=email, codigo=codigo[:6] + '...',
                ref=codes[codigo]['ref'])
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


def _log_pedido(evento, **campos):
    import datetime
    try:
        with open(ORDERS_LOG, 'a', encoding='utf-8') as f:
            f.write(json.dumps({'ts': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                                'evento': evento, **campos}, ensure_ascii=False) + '\n')
    except Exception:
        pass


def _rodar_scan_async(tipo, alvo, email, ref):
    import threading

    def _job():
        try:
            p = subprocess.run([sys.executable, 'run_scan.py', tipo, alvo, email, ref],
                               capture_output=True, text=True, timeout=600,
                               cwd=os.path.dirname(os.path.abspath(__file__)))
            _log_pedido('scan_concluido', email=email, tipo=tipo, alvo=alvo, ref=ref,
                        ok=p.returncode == 0, saida=(p.stdout or '')[-300])
        except Exception as e:
            _log_pedido('scan_falha', email=email, tipo=tipo, alvo=alvo, ref=ref, erro=str(e))
    threading.Thread(target=_job, daemon=False).start()


def _admin_ok():
    import hmac
    tok = request.headers.get('X-Admin-Token', '') or (request.get_json(force=True, silent=True) or {}).get('admin_token', '')
    return bool(ADMIN_TOKEN) and hmac.compare_digest(tok, ADMIN_TOKEN)


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
    _log_pedido('resgate', email=email, tipo=tipo, alvo=alvo, ref=reg.get('ref', 'hotmart'))
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
    _log_pedido('compra_aprovada', email=email, codigo=codigo[:6] + '...', ref=codes[codigo]['ref'])
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


@app.get('/api/fila')
def fila():
    """Admin: pedidos pendentes + códigos emitidos + log de eventos."""
    if not _admin_ok():
        return jsonify(ok=False, erro='não autorizado'), 401
    codes = _load_codes()
    resumo = {k: {'email': v.get('email'), 'usado': v.get('usado'), 'ref': v.get('ref')}
              for k, v in codes.items()}
    try:
        with open(ORDERS_LOG, encoding='utf-8') as f:
            log = [json.loads(l) for l in f if l.strip()][-50:]
    except Exception:
        log = []
    return jsonify(ok=True, pendentes=_load_pending(), codigos=resumo, log=log)


@app.post('/api/teste-scan')
def teste_scan():
    """Admin: roda um scan de teste sem pagamento (exige X-Admin-Token)."""
    if not _admin_ok():
        return jsonify(ok=False, erro='não autorizado'), 401
    dados = request.get_json(force=True, silent=True) or {}
    email = (dados.get('email') or '').strip().lower()
    tipo = (dados.get('tipo') or '').strip()
    alvo = (dados.get('alvo') or '').strip()
    if not EMAIL_RE.match(email):
        return jsonify(ok=False, erro='E-mail inválido'), 400
    if not validar_alvo(tipo, alvo):
        return jsonify(ok=False, erro='Alvo inválido para o tipo'), 400
    _log_pedido('teste_scan', email=email, tipo=tipo, alvo=alvo)
    _rodar_scan_async(tipo, alvo, email, 'teste-admin')
    return jsonify(ok=True, msg='Scan de teste disparado. Verifique o e-mail em alguns minutos.')


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
