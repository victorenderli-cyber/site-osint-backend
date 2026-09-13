# Backend da automação (Hotmart + scan passivo + e-mail, grátis no Render)

## Fluxo
1. Site chama `POST /api/iniciar` {email, tipo, alvo} → registra pedido pendente e devolve o checkout Hotmart com e-mail pré-preenchido.
2. Cliente paga → Hotmart chama `POST /webhook/hotmart?hottok=SEGREDO` no evento de compra aprovada.
3. Backend cruza o e-mail do comprador, roda `run_scan.py` (só OSINT passivo) e envia o relatório por e-mail. Sem intervenção manual.

## Configurar
1. Hotmart → produto "Consulta OSINT única — R$ 49,90" → **Ferramentas → Webhook**: `https://SEU-BACKEND/webhook/hotmart?hottok=UM-SEGREDO-FORTE`, evento de compra aprovada.
2. Render.com → New → Web Service → repo `site-osint-backend` → envs: `HOTMART_HOTTOK`, `HOTMART_CHECKOUT_URL` + e-mail (`MAKE_WEBHOOK_URL` ou `BREVO_API_KEY`/`BREVO_SENDER` ou SMTP).
3. `BACKEND_URL` no `app.js` do site + deploy.

## Alternativa: Mercado Pago ("Já paguei")
Cliente informa o ID do pagamento; `POST /api/confirmar` confere `approved` na API. Exige `MP_ACCESS_TOKEN`.

## Segurança
- hottok validado no servidor; validação de e-mail/username/domínio (sem shell injection).
- Scan estritamente passivo; sem port scan ou brute force.

## Testar local
`pip install -r requirements.txt && python app.py` → `GET /api/status`
