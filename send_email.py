"""Envio do relatório por e-mail via SMTP (ex: Gmail com senha de app)."""
import os
import smtplib
from email.message import EmailMessage

SMTP_HOST = os.environ.get('SMTP_HOST', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', '587'))
SMTP_USER = os.environ.get('SMTP_USER', '')
SMTP_PASS = os.environ.get('SMTP_PASS', '')
REPORT_FROM = os.environ.get('REPORT_FROM', SMTP_USER)


def enviar_relatorio(destinatario, assunto, corpo_txt):
    if not (SMTP_USER and SMTP_PASS):
        raise RuntimeError('SMTP_USER/SMTP_PASS não configurados')
    msg = EmailMessage()
    msg['From'] = REPORT_FROM
    msg['To'] = destinatario
    msg['Subject'] = assunto
    msg.set_content(corpo_txt)
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as s:
        s.starttls()
        s.login(SMTP_USER, SMTP_PASS)
        s.send_message(msg)
