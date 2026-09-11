"""Cadastro automático na AbacatePay: produto + webhook. Rode UMA vez.

Uso (chave via env, nunca no comando):
  set ABACATEPAY_API_KEY=sua-key  (Windows CMD)
  $env:ABACATEPAY_API_KEY="sua-key"  (PowerShell)
  python setup_abacatepay.py https://SEU-BACKEND.onrender.com SEU-SEGREDO-FORTE

Cria:
- Produto "Consulta OSINT única" R$ 49,90 (externalId consulta-osint-unica)
- Webhook transparent.completed → https://SEU-BACKEND/webhook/abacatepay
"""
import os
import sys

import requests

BASE = 'https://api.abacatepay.com/v2'


def main():
    if len(sys.argv) != 3:
        print('Uso: python setup_abacatepay.py https://SEU-BACKEND SEGREDO-WEBHOOK')
        return 2
    backend, secret = sys.argv[1].rstrip('/'), sys.argv[2]
    key = os.environ.get('ABACATEPAY_API_KEY', '')
    if not key:
        print('Defina ABACATEPAY_API_KEY no ambiente primeiro.')
        return 2
    h = {'Authorization': f'Bearer {key}'}

    prod = requests.post(f'{BASE}/products/create', headers=h, json={
        'externalId': 'consulta-osint-unica',
        'name': 'Consulta OSINT única',
        'price': 4990, 'currency': 'BRL',
        'description': 'Verificação pontual de 1 e-mail, username ou domínio',
    }, timeout=20)
    print('produto:', prod.status_code, prod.text[:200])

    wh = requests.post(f'{BASE}/webhooks/create', headers=h, json={
        'name': 'osint-auto',
        'endpoint': f'{backend}/webhook/abacatepay',
        'secret': secret,
        'events': ['transparent.completed'],
    }, timeout=20)
    print('webhook:', wh.status_code, wh.text[:200])
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
