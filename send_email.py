"""Envio do relatório por e-mail. Ordem de preferência:
1. MAKE_WEBHOOK_URL (Make.com: Webhook -> Gmail, sem senha, só OAuth por clique)
2. BREVO_API_KEY (API HTTPS da Brevo, 300/dia grátis)
3. SMTP (Gmail + senha de app; bloqueado no Render free, ok em VPS/local)
"""
import os

import requests

SMTP_HOST = os.environ.get('SMTP_HOST', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', '587'))
SMTP_USER = os.environ.get('SMTP_USER', '')
SMTP_PASS = os.environ.get('SMTP_PASS', '')
REPORT_FROM = os.environ.get('REPORT_FROM', SMTP_USER)
MAKE_WEBHOOK_URL = os.environ.get('MAKE_WEBHOOK_URL', '')
BREVO_API_KEY = os.environ.get('BREVO_API_KEY', '')
BREVO_SENDER = os.environ.get('BREVO_SENDER', REPORT_FROM or 'victorenderli@gmail.com')


def _via_make(destinatario, assunto, corpo_txt):
    r = requests.post(MAKE_WEBHOOK_URL, json={
        'to': destinatario, 'subject': assunto, 'text': corpo_txt,
    }, timeout=30)
    if r.status_code >= 300:
        raise RuntimeError(f'Make retornou {r.status_code}')


def _via_brevo(destinatario, assunto, corpo_txt):
    r = requests.post('https://api.brevo.com/v3/smtp/email',
                      headers={'api-key': BREVO_API_KEY,
                               'Content-Type': 'application/json'},
                      json={'sender': {'email': BREVO_SENDER},
                            'to': [{'email': destinatario}],
                            'subject': assunto,
                            'textContent': corpo_txt}, timeout=30)
    if r.status_code >= 300:
        raise RuntimeError(f'Brevo retornou {r.status_code}: {r.text[:200]}')


def _via_smtp(destinatario, assunto, corpo_txt):
    import smtplib
    from email.message import EmailMessage
    if not (SMTP_USER and SMTP_PASS):
        raise RuntimeError('Nenhum provedor de e-mail configurado')
    msg = EmailMessage()
    msg['From'] = REPORT_FROM
    msg['To'] = destinatario
    msg['Subject'] = assunto
    msg.set_content(corpo_txt)
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as s:
        s.starttls()
        s.login(SMTP_USER, SMTP_PASS)
        s.send_message(msg)


def enviar_relatorio(destinatario, assunto, corpo_txt):
    if MAKE_WEBHOOK_URL:
        return _via_make(destinatario, assunto, corpo_txt)
    if BREVO_API_KEY:
        return _via_brevo(destinatario, assunto, corpo_txt)
    return _via_smtp(destinatario, assunto, corpo_txt)
