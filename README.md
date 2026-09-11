# Backend da automação (grátis no Render)

## Opção recomendada: AbacatePay (Pix automático, mais fácil)
1. Crie conta em abacatepay.com → pegue a **API key** → `ABACATEPAY_API_KEY`.
2. Suba este backend no Render (base abaixo) e cadastre o webhook via API:
   `POST https://api.abacatepay.com/v2/webhooks/create` com
   `endpoint=https://SEU-BACKEND/webhook/abacatepay`,
   `secret=UM-SEGREDO-FORTE` (= `ABACATEPAY_WEBHOOK_SECRET`) e
   `events=["transparent.completed"]`.
   Teste antes em **Dev mode** com `POST /transparents/simulate-payment`.
3. Coloque a URL do backend em `BACKEND_URL` no `app.js` e rode o deploy.
4. Pronto: o site gera o QR de R$ 49,90 sozinho; ao pagar, o webhook dispara scan + e-mail sem você fazer nada.

## Opção alternativa: Mercado Pago ("Já paguei")
1. Cliente paga no link e informa o **ID do pagamento** no site.
2. `POST /api/confirmar` confere o status na API (`approved`) antes de rodar.
3. Exige `MP_ACCESS_TOKEN`. Taxas maiores e um passo manual do cliente.

## Comparativo rápido
| | AbacatePay ✅ | Mercado Pago | Efí (Gerencianet) | Stripe |
|---|---|---|---|---|
| Taxa Pix | R$ 0,80 fixo | ~4,99% + taxa | % por transação | ~4,99% |
| Webhook fácil | Sim (HMAC simples) | Sim | Exige mTLS + certificado | Sim |
| Burocracia | Baixa | Média | Alta (conta PJ, mTLS) | Alta (verificação) |
| Ideal para | Consulta R$ 49,90 | Alternativa | Volume alto PJ | Cartão internacional |

## Configurar base (vale para as duas opções)
1. Gmail → senha de app → `SMTP_USER`/`SMTP_PASS` (+ `REPORT_FROM`).
2. Render.com → New → Web Service → suba esta pasta → Build: `pip install -r requirements.txt` → Start: `python app.py` → envs do `.env.example`.
3. `BACKEND_URL` no `app.js` + deploy do site.

## Segurança incluída
- Validação de e-mail, username e domínio (regex, sem shell injection — sem `shell=True`).
- Status do pagamento conferido **no servidor**, nunca no navegador.
- Scan estritamente passivo (maigret/holehe/subfinder/theHarvester); sem scan de portas ou brute force.

## Testar local
`pip install -r requirements.txt && python app.py` → `GET /api/status`
