LifeBalance.Api — Stripe Webhook Setup (Produção)

Passos para configurar o Webhook do Stripe e chaves de produção.

1) URL do Webhook
- Endpoint: `https://SEU-BACKEND/api/billing/webhook`
- No Stripe Dashboard: Developers → Webhooks → Add endpoint → Endpoint URL acima.
- Selecione eventos:
  - `checkout.session.completed`
  - `customer.subscription.created`
  - `customer.subscription.updated`
  - `customer.subscription.deleted`

2) Copiar o Webhook Secret (whsec)
- Após criar o endpoint, copie o `Signing secret` (ex.: `whsec_...`).
- Defina na API de produção de uma das formas:
  - Variável de ambiente: `STRIPE_WEBHOOK_SECRET=whsec_...`
  - Ou arquivo de configuração: `appsettings.Production.json` → `Stripe:WebhookSecret` (não committe chaves reais).

3) Chave secreta do Stripe (live)
- Defina a chave secreta de produção:
  - Variável de ambiente: `STRIPE_SECRET_KEY=sk_live_...`
  - Ou `appsettings.Production.json` → `Stripe:SecretKey`

4) Price IDs (opcional, recomendado)
- Defina os `price` IDs live para mapear plano corretamente:
  - `Stripe:MonthlyPriceId=price_live_monthly_...`
  - `Stripe:AnnualPriceId=price_live_annual_...`

5) URLs do Front/Back (CORS e redirects)
- `FrontendOrigin`: `https://SEU-FRONTEND`
- `BackendBaseUrl`: `https://SEU-BACKEND`
- Payment Links/Checkout devem redirecionar para:
  - Sucesso: `https://SEU-FRONTEND/dashboard?checkout=success`
  - Cancelamento: `https://SEU-FRONTEND/dashboard?checkout=cancel`

6) Verificação em produção
- Após um pagamento, a API deve registrar logs como:
  - `Stripe webhook event received: type=checkout.session.completed ...`
  - `Fetched sub from session: subId=... status=... priceId=... plan=...`
  - `Inserted/Updated subscription row ...`
- O front consulta `GET /api/billing/subscription` e deve retornar `active=true` quando a assinatura estiver ativa/trialing.

7) Ambiente de desenvolvimento (opcional)
- `stripe listen --forward-to http://localhost:5104/api/billing/webhook`
- Use as chaves/test links e configure `STRIPE_WEBHOOK_SECRET` conforme mostrado pelo Stripe CLI.

Importante: Nunca committe chaves reais (sk_live, whsec) no repositório. Use variáveis de ambiente no servidor ou um gerenciador de segredos seguro.

