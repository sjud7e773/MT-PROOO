# MTProto Server - Servidor Real para Telegram

Este servidor implementa autenticação MTProto **real** do Telegram, permitindo:
- ✅ Código numérico de 5 dígitos (como apps de clonagem profissionais)
- ✅ Sincronização automática de grupos e canais
- ✅ Acesso ao histórico de mensagens
- ✅ Encaminhamento de mensagens
- ✅ Suporte a 2FA (verificação em duas etapas)

## Por que um servidor separado?

O protocolo MTProto do Telegram requer conexões TCP persistentes, que **não são suportadas** por:
- Supabase Edge Functions
- Cloudflare Workers
- Vercel Edge Functions
- Qualquer ambiente serverless

Por isso, este servidor precisa rodar em um ambiente com suporte a conexões persistentes.

## Deploy Rápido

### Opção 1: Railway (Recomendado)

[![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/new)

1. Crie uma conta no [Railway](https://railway.app)
2. Clique em "New Project" → "Deploy from GitHub repo"
3. Conecte este repositório (ou faça upload da pasta `mtproto-server`)
4. Configure as variáveis de ambiente:

```env
TELEGRAM_API_ID=seu_api_id
TELEGRAM_API_HASH=seu_api_hash
MTPROTO_SERVER_SECRET=uma_senha_secreta_forte
PORT=3000
```

5. Deploy automático! Anote a URL gerada (ex: `https://seu-app.railway.app`)

### Opção 2: Render

1. Crie uma conta no [Render](https://render.com)
2. Novo Web Service → Conecte o repositório
3. Configure:
   - Build Command: `npm install`
   - Start Command: `npm start`
4. Adicione as variáveis de ambiente
5. Deploy! Anote a URL

### Opção 3: Fly.io

```bash
# Instale o CLI
curl -L https://fly.io/install.sh | sh

# Login
fly auth login

# Na pasta mtproto-server:
fly launch

# Configure secrets
fly secrets set TELEGRAM_API_ID=xxx TELEGRAM_API_HASH=xxx MTPROTO_SERVER_SECRET=xxx

# Deploy
fly deploy
```

### Opção 4: VPS (DigitalOcean, Linode, etc.)

```bash
# Clone o repositório
git clone <repo>
cd mtproto-server

# Instale dependências
npm install

# Configure variáveis (crie .env)
echo "TELEGRAM_API_ID=xxx" >> .env
echo "TELEGRAM_API_HASH=xxx" >> .env
echo "MTPROTO_SERVER_SECRET=xxx" >> .env

# Execute com PM2 (recomendado para produção)
npm install -g pm2
pm2 start server.js --name mtproto
pm2 save
pm2 startup
```

## Obtendo API ID e Hash

1. Acesse https://my.telegram.org
2. Faça login com seu número de telefone
3. Vá em "API Development Tools"
4. Crie um novo aplicativo
5. Copie o `api_id` e `api_hash`

## Configuração no Lovable

Após o deploy, adicione o secret `MTPROTO_SERVER_URL` no Lovable com a URL do seu servidor:

```
MTPROTO_SERVER_URL=https://seu-servidor.railway.app
```

E também `MTPROTO_SERVER_SECRET` com a mesma senha configurada no servidor.

## Endpoints da API

Todos os endpoints requerem o header `X-Server-Secret` com o valor de `MTPROTO_SERVER_SECRET`.

### POST /send-code
Envia código de verificação para o número.

```json
{
  "phone_number": "+5511999999999",
  "user_id": "uuid-do-usuario"
}
```

### POST /verify-code
Verifica o código e autentica.

```json
{
  "phone_number": "+5511999999999",
  "code": "12345",
  "user_id": "uuid-do-usuario",
  "password": "opcional-se-2fa"
}
```

### POST /get-dialogs
Retorna lista de grupos e canais.

```json
{
  "session_string": "sessao-criptografada"
}
```

### POST /get-history
Retorna histórico de mensagens.

```json
{
  "session_string": "sessao-criptografada",
  "chat_id": 123456789,
  "access_hash": "opcional",
  "limit": 100,
  "offset_id": 0
}
```

## Segurança

- O `MTPROTO_SERVER_SECRET` deve ser uma senha forte e única
- As sessões são criptografadas antes de serem armazenadas
- Use HTTPS em produção (Railway/Render já fornecem automaticamente)
- Considere limitar IPs de origem se possível

## Troubleshooting

### Erro "PHONE_NUMBER_FLOOD"
Aguarde alguns minutos e tente novamente. Isso acontece após muitas tentativas.

### Erro "SESSION_PASSWORD_NEEDED"
A conta tem 2FA ativado. O usuário precisa digitar a senha.

### Erro "AUTH_KEY_UNREGISTERED"
A sessão expirou. Faça login novamente.

## Licença

MIT
