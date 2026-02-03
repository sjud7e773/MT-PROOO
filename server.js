/**
 * MTProto Server v2.0 - Servidor ROBUSTO para Telegram
 * 
 * Melhorias:
 * - Reconexão automática
 * - Health checks completos
 * - Melhor tratamento de erros
 * - Pool de conexões
 * - Logs detalhados
 * 
 * Deploy em: Railway, Render, Fly.io, ou VPS
 */

import express from 'express';
import cors from 'cors';
import { TelegramClient, Api } from 'telegram';
import { StringSession } from 'telegram/sessions/index.js';
import crypto from 'crypto';

const app = express();
app.use(cors());
app.use(express.json({ limit: '50mb' }));

// ==================== CONFIGURATION ====================
const API_ID = parseInt(process.env.TELEGRAM_API_ID || '0');
const API_HASH = process.env.TELEGRAM_API_HASH || '';
const SERVER_SECRET = process.env.MTPROTO_SERVER_SECRET || 'change-me-in-production';
const PORT = process.env.PORT || 3000;

// ==================== STATE MANAGEMENT ====================
const pendingLogins = new Map();
const clientPool = new Map(); // Pool de clientes ativos
const SESSION_TTL = 30 * 60 * 1000; // 30 minutos de inatividade
const LOGIN_TTL = 15 * 60 * 1000; // 15 minutos para login

// Stats para monitoramento
const serverStats = {
  startedAt: Date.now(),
  totalRequests: 0,
  successfulRequests: 0,
  failedRequests: 0,
  activeConnections: 0,
  lastError: null,
  lastSuccessfulRequest: null,
};

// ==================== HELPERS ====================
function encrypt(text, key) {
  const cipher = crypto.createCipheriv('aes-256-cbc', 
    crypto.createHash('sha256').update(key).digest(), 
    Buffer.alloc(16, 0)
  );
  return cipher.update(text, 'utf8', 'base64') + cipher.final('base64');
}

function decrypt(encrypted, key) {
  try {
    const decipher = crypto.createDecipheriv('aes-256-cbc',
      crypto.createHash('sha256').update(key).digest(),
      Buffer.alloc(16, 0)
    );
    return decipher.update(encrypted, 'base64', 'utf8') + decipher.final('utf8');
  } catch {
    return null;
  }
}

function log(level, message, data = {}) {
  const timestamp = new Date().toISOString();
  const logEntry = { timestamp, level, message, ...data };
  console.log(JSON.stringify(logEntry));
}

// Middleware para verificar secret
function verifySecret(req, res, next) {
  const authHeader = req.headers['x-server-secret'];
  if (authHeader !== SERVER_SECRET) {
    log('warn', 'Unauthorized request', { ip: req.ip });
    return res.status(401).json({ error: 'Unauthorized', success: false });
  }
  serverStats.totalRequests++;
  next();
}

// Limpar recursos antigos periodicamente
setInterval(() => {
  const now = Date.now();
  
  // Limpar logins pendentes expirados
  for (const [key, value] of pendingLogins.entries()) {
    if (now - value.createdAt > LOGIN_TTL) {
      log('info', 'Cleaning expired pending login', { key });
      try { value.client?.disconnect(); } catch {}
      pendingLogins.delete(key);
    }
  }
  
  // Limpar clientes inativos
  for (const [key, value] of clientPool.entries()) {
    if (now - value.lastActive > SESSION_TTL) {
      log('info', 'Cleaning inactive client', { key });
      try { value.client?.disconnect(); } catch {}
      clientPool.delete(key);
    }
  }
  
  serverStats.activeConnections = clientPool.size + pendingLogins.size;
}, 60 * 1000); // A cada minuto

// ==================== HEALTH CHECK ====================
app.get('/health', (req, res) => {
  const uptime = Math.floor((Date.now() - serverStats.startedAt) / 1000);
  
  res.json({ 
    status: 'ok',
    version: '2.0.0',
    uptime_seconds: uptime,
    api_configured: !!(API_ID && API_HASH),
    secret_configured: SERVER_SECRET !== 'change-me-in-production',
    stats: {
      total_requests: serverStats.totalRequests,
      successful: serverStats.successfulRequests,
      failed: serverStats.failedRequests,
      active_connections: clientPool.size,
      pending_logins: pendingLogins.size,
    },
    last_error: serverStats.lastError,
    last_success: serverStats.lastSuccessfulRequest,
    timestamp: new Date().toISOString(),
  });
});

// ==================== GET CLIENT (com reconexão) ====================
async function getOrCreateClient(sessionString, identifier) {
  // Verificar se já existe no pool
  if (clientPool.has(identifier)) {
    const pooled = clientPool.get(identifier);
    pooled.lastActive = Date.now();
    
    // Verificar se ainda está conectado
    if (pooled.client.connected) {
      return pooled.client;
    }
    
    // Tentar reconectar
    log('info', 'Reconnecting pooled client', { identifier });
    try {
      await pooled.client.connect();
      return pooled.client;
    } catch (e) {
      log('warn', 'Reconnection failed, creating new client', { identifier, error: e.message });
      clientPool.delete(identifier);
    }
  }
  
  // Criar novo cliente
  const stringSession = new StringSession(sessionString);
  const client = new TelegramClient(stringSession, API_ID, API_HASH, {
    connectionRetries: 5,
    retryDelay: 1000,
    autoReconnect: true,
    useWSS: false,
  });
  
  await client.connect();
  
  // Adicionar ao pool
  clientPool.set(identifier, {
    client,
    lastActive: Date.now(),
  });
  
  serverStats.activeConnections = clientPool.size;
  
  return client;
}

// ==================== SEND CODE ====================
app.post('/send-code', verifySecret, async (req, res) => {
  try {
    const { phone_number, user_id } = req.body;
    
    if (!phone_number) {
      return res.status(400).json({ error: 'phone_number is required', success: false });
    }

    if (!API_ID || !API_HASH) {
      return res.status(500).json({ error: 'API credentials not configured', success: false });
    }

    log('info', 'Sending code', { phone: phone_number.substring(0, 6) + '...' });

    const stringSession = new StringSession('');
    const client = new TelegramClient(stringSession, API_ID, API_HASH, {
      connectionRetries: 5,
      useWSS: false,
    });

    await client.connect();

    const result = await client.sendCode(
      { apiId: API_ID, apiHash: API_HASH },
      phone_number
    );

    log('info', 'Code sent successfully', { hash: result.phoneCodeHash.substring(0, 8) + '...' });

    const loginId = `${user_id}_${phone_number}`;
    pendingLogins.set(loginId, {
      client,
      phoneCodeHash: result.phoneCodeHash,
      phoneNumber: phone_number,
      createdAt: Date.now(),
    });

    serverStats.successfulRequests++;
    serverStats.lastSuccessfulRequest = new Date().toISOString();

    res.json({
      success: true,
      phone_code_hash: result.phoneCodeHash,
      code_type: result.type?.className || 'sms',
      timeout: result.timeout || 120,
      message: 'Código enviado! Verifique seu Telegram (5 dígitos numéricos).',
    });
  } catch (error) {
    log('error', 'sendCode failed', { error: error.message });
    serverStats.failedRequests++;
    serverStats.lastError = { message: error.message, timestamp: new Date().toISOString() };
    
    const errorMsg = error.message || String(error);
    
    if (errorMsg.includes('PHONE_NUMBER_INVALID')) {
      return res.status(400).json({ error: 'Número inválido. Use formato internacional: +5511999999999', success: false });
    }
    if (errorMsg.includes('PHONE_NUMBER_FLOOD')) {
      return res.status(429).json({ error: 'Muitas tentativas. Aguarde alguns minutos.', success: false });
    }
    if (errorMsg.includes('PHONE_NUMBER_BANNED')) {
      return res.status(403).json({ error: 'Este número está banido.', success: false });
    }
    
    res.status(500).json({ error: errorMsg, success: false });
  }
});

// ==================== VERIFY CODE ====================
app.post('/verify-code', verifySecret, async (req, res) => {
  try {
    const { phone_number, code, password, user_id, phone_code_hash } = req.body;
    
    if (!phone_number || !code) {
      return res.status(400).json({ error: 'phone_number and code are required', success: false });
    }

    const loginId = `${user_id}_${phone_number}`;
    const pending = pendingLogins.get(loginId);

    if (!pending) {
      return res.status(400).json({ error: 'Sessão não encontrada. Solicite o código novamente.', success: false });
    }

    if (Date.now() - pending.createdAt > LOGIN_TTL) {
      pendingLogins.delete(loginId);
      try { await pending.client.disconnect(); } catch {}
      return res.status(400).json({ error: 'Código expirado. Solicite novamente.', success: false });
    }

    log('info', 'Verifying code', { phone: phone_number.substring(0, 6) + '...' });

    const client = pending.client;
    let user;

    try {
      user = await client.invoke(
        new Api.auth.SignIn({
          phoneNumber: phone_number,
          phoneCodeHash: phone_code_hash || pending.phoneCodeHash,
          phoneCode: code.toString().trim(),
        })
      );
    } catch (signInError) {
      const errMsg = signInError.message || String(signInError);
      log('warn', 'SignIn error', { error: errMsg });

      if (errMsg.includes('SESSION_PASSWORD_NEEDED')) {
        if (!password) {
          return res.json({
            success: false,
            requires_2fa: true,
            error: 'Verificação em duas etapas necessária. Digite sua senha.',
          });
        }

        try {
          const passwordResult = await client.invoke(new Api.account.GetPassword());
          const passwordCheck = await client.computePasswordCheck(passwordResult, password);
          user = await client.invoke(new Api.auth.CheckPassword({ password: passwordCheck }));
        } catch (twoFaError) {
          const twoFaMsg = twoFaError.message || '';
          if (twoFaMsg.includes('PASSWORD_HASH_INVALID')) {
            return res.status(400).json({ error: 'Senha 2FA incorreta.', success: false });
          }
          throw twoFaError;
        }
      } else if (errMsg.includes('PHONE_CODE_INVALID')) {
        return res.status(400).json({ error: 'Código inválido. Verifique os 5 dígitos.', success: false });
      } else if (errMsg.includes('PHONE_CODE_EXPIRED')) {
        return res.status(400).json({ error: 'Código expirado. Solicite novamente.', success: false });
      } else {
        throw signInError;
      }
    }

    const me = await client.getMe();
    log('info', 'Authenticated successfully', { username: me.username });

    const sessionString = client.session.save();
    const encryptedSession = encrypt(sessionString, SERVER_SECRET);

    // Mover para pool de clientes ativos
    clientPool.set(loginId, {
      client,
      lastActive: Date.now(),
    });
    pendingLogins.delete(loginId);

    serverStats.successfulRequests++;
    serverStats.lastSuccessfulRequest = new Date().toISOString();

    res.json({
      success: true,
      session_string: encryptedSession,
      user: {
        id: me.id?.value ? Number(me.id.value) : Number(me.id),
        firstName: me.firstName,
        lastName: me.lastName,
        username: me.username,
        phone: me.phone,
      },
    });
  } catch (error) {
    log('error', 'verify failed', { error: error.message });
    serverStats.failedRequests++;
    serverStats.lastError = { message: error.message, timestamp: new Date().toISOString() };
    res.status(500).json({ error: error.message, success: false });
  }
});

// ==================== GET DIALOGS ====================
app.post('/get-dialogs', verifySecret, async (req, res) => {
  try {
    const { session_string, user_id, phone_number } = req.body;
    
    if (!session_string) {
      return res.status(400).json({ error: 'session_string is required', success: false });
    }

    const decryptedSession = decrypt(session_string, SERVER_SECRET);
    if (!decryptedSession) {
      return res.status(400).json({ error: 'Invalid session', success: false });
    }

    log('info', 'Fetching dialogs');

    const identifier = `${user_id}_${phone_number}`;
    const client = await getOrCreateClient(decryptedSession, identifier);

    const dialogs = await client.getDialogs({ limit: 300 });
    log('info', 'Got dialogs', { count: dialogs.length });

    const chats = dialogs
      .filter(d => {
        const entity = d.entity;
        if (!entity) return false;
        return entity.className === 'Channel' || 
               entity.className === 'Chat' ||
               entity.megagroup === true;
      })
      .map(d => {
        const entity = d.entity;
        
        let chatType = 'group';
        if (entity.broadcast) chatType = 'channel';
        else if (entity.megagroup) chatType = 'supergroup';

        return {
          chat_id: entity.id?.value ? Number(entity.id.value) : Number(entity.id),
          access_hash: entity.accessHash?.value 
            ? entity.accessHash.value.toString() 
            : (entity.accessHash ? entity.accessHash.toString() : null),
          title: entity.title || 'Sem título',
          username: entity.username || null,
          type: chatType,
          is_creator: entity.creator || false,
          is_admin: !!(entity.creator || entity.adminRights),
          member_count: entity.participantsCount || null,
          last_message_id: d.message?.id || null,
          photo: entity.photo ? true : false,
        };
      });

    serverStats.successfulRequests++;
    serverStats.lastSuccessfulRequest = new Date().toISOString();

    res.json({
      success: true,
      dialogs: chats,
      total: chats.length,
      groups: chats.filter(c => c.type !== 'channel').length,
      channels: chats.filter(c => c.type === 'channel').length,
    });
  } catch (error) {
    log('error', 'getDialogs failed', { error: error.message });
    serverStats.failedRequests++;
    serverStats.lastError = { message: error.message, timestamp: new Date().toISOString() };
    
    if (error.message?.includes('AUTH_KEY_UNREGISTERED') || error.message?.includes('SESSION_REVOKED')) {
      return res.status(401).json({ error: 'Sessão expirada. Faça login novamente.', success: false });
    }
    
    res.status(500).json({ error: error.message, success: false });
  }
});

// ==================== GET CHAT INFO (Validação de ID) ====================
app.post('/get-chat-info', verifySecret, async (req, res) => {
  try {
    const { session_string, chat_id, user_id, phone_number } = req.body;
    
    if (!session_string || chat_id === undefined) {
      return res.status(400).json({ error: 'session_string and chat_id are required', success: false });
    }

    const decryptedSession = decrypt(session_string, SERVER_SECRET);
    if (!decryptedSession) {
      return res.status(400).json({ error: 'Invalid session', success: false });
    }

    log('info', 'Getting chat info', { chat_id });

    const identifier = `${user_id}_${phone_number}`;
    const client = await getOrCreateClient(decryptedSession, identifier);

    // Buscar entidade pelo ID
    let entity;
    try {
      entity = await client.getEntity(chat_id);
    } catch (e) {
      // Tentar com -100 prefix para canais/supergrupos
      if (!String(chat_id).startsWith('-100')) {
        try {
          entity = await client.getEntity(Number(`-100${Math.abs(chat_id)}`));
        } catch {
          return res.status(404).json({ error: 'Chat não encontrado ou você não tem acesso', success: false });
        }
      } else {
        return res.status(404).json({ error: 'Chat não encontrado ou você não tem acesso', success: false });
      }
    }

    let chatType = 'group';
    if (entity.broadcast) chatType = 'channel';
    else if (entity.megagroup) chatType = 'supergroup';
    else if (entity.className === 'Chat') chatType = 'group';

    const chatInfo = {
      chat_id: entity.id?.value ? Number(entity.id.value) : Number(entity.id),
      access_hash: entity.accessHash?.value 
        ? entity.accessHash.value.toString() 
        : (entity.accessHash ? entity.accessHash.toString() : null),
      title: entity.title || entity.firstName || 'Sem título',
      username: entity.username || null,
      type: chatType,
      is_creator: entity.creator || false,
      is_admin: !!(entity.creator || entity.adminRights),
      member_count: entity.participantsCount || null,
    };

    serverStats.successfulRequests++;
    serverStats.lastSuccessfulRequest = new Date().toISOString();

    res.json({
      success: true,
      chat: chatInfo,
    });
  } catch (error) {
    log('error', 'getChatInfo failed', { error: error.message });
    serverStats.failedRequests++;
    serverStats.lastError = { message: error.message, timestamp: new Date().toISOString() };
    res.status(500).json({ error: error.message, success: false });
  }
});

// ==================== GET HISTORY ====================
app.post('/get-history', verifySecret, async (req, res) => {
  try {
    const { session_string, chat_id, access_hash, limit = 100, offset_id = 0, user_id, phone_number, media_filter } = req.body;
    
    if (!session_string || !chat_id) {
      return res.status(400).json({ error: 'session_string and chat_id are required', success: false });
    }

    const decryptedSession = decrypt(session_string, SERVER_SECRET);
    if (!decryptedSession) {
      return res.status(400).json({ error: 'Invalid session', success: false });
    }

    log('info', 'Fetching history', { chat_id, limit, offset_id, media_filter });

    const identifier = `${user_id}_${phone_number}`;
    const client = await getOrCreateClient(decryptedSession, identifier);

    // Build peer
    let peer;
    if (access_hash) {
      peer = new Api.InputPeerChannel({
        channelId: BigInt(chat_id),
        accessHash: BigInt(access_hash),
      });
    } else {
      peer = new Api.InputPeerChat({ chatId: BigInt(Math.abs(chat_id)) });
    }

    const messages = await client.getMessages(peer, { limit: Math.min(limit, 100), offsetId: offset_id });

    // Filtrar por tipo de mídia se especificado
    let filteredMessages = messages;
    if (media_filter) {
      filteredMessages = messages.filter(m => {
        if (!m.media) return false;
        
        const mediaClass = m.media.className;
        if (media_filter === 'video') {
          return mediaClass === 'MessageMediaDocument' && 
                 m.media.document?.mimeType?.startsWith('video/');
        }
        if (media_filter === 'photo') {
          return mediaClass === 'MessageMediaPhoto';
        }
        if (media_filter === 'media') {
          return mediaClass === 'MessageMediaPhoto' || 
                 (mediaClass === 'MessageMediaDocument' && 
                  (m.media.document?.mimeType?.startsWith('video/') || 
                   m.media.document?.mimeType?.startsWith('image/')));
        }
        return true;
      });
    }

    serverStats.successfulRequests++;
    serverStats.lastSuccessfulRequest = new Date().toISOString();

    res.json({
      success: true,
      messages: filteredMessages.map(m => ({
        id: m.id,
        date: m.date,
        message: m.message,
        from_id: m.fromId?.userId?.value ? Number(m.fromId.userId.value) : null,
        has_media: !!m.media,
        media_type: m.media?.className || null,
        mime_type: m.media?.document?.mimeType || null,
      })),
      total_fetched: messages.length,
      filtered_count: filteredMessages.length,
      has_more: messages.length === Math.min(limit, 100),
    });
  } catch (error) {
    log('error', 'getHistory failed', { error: error.message });
    serverStats.failedRequests++;
    serverStats.lastError = { message: error.message, timestamp: new Date().toISOString() };
    res.status(500).json({ error: error.message, success: false });
  }
});

// ==================== FORWARD MESSAGES ====================
app.post('/forward-messages', verifySecret, async (req, res) => {
  try {
    const { 
      session_string, 
      from_chat_id, 
      to_chat_id, 
      message_ids, 
      from_access_hash, 
      to_access_hash,
      user_id,
      phone_number,
      drop_author = true 
    } = req.body;
    
    if (!session_string || !from_chat_id || !to_chat_id || !message_ids?.length) {
      return res.status(400).json({ error: 'Missing required parameters', success: false });
    }

    const decryptedSession = decrypt(session_string, SERVER_SECRET);
    if (!decryptedSession) {
      return res.status(400).json({ error: 'Invalid session', success: false });
    }

    log('info', 'Forwarding messages', { 
      from: from_chat_id, 
      to: to_chat_id, 
      count: message_ids.length 
    });

    const identifier = `${user_id}_${phone_number}`;
    const client = await getOrCreateClient(decryptedSession, identifier);

    // Build peers
    const fromPeer = from_access_hash 
      ? new Api.InputPeerChannel({ channelId: BigInt(from_chat_id), accessHash: BigInt(from_access_hash) })
      : new Api.InputPeerChat({ chatId: BigInt(Math.abs(from_chat_id)) });

    const toPeer = to_access_hash
      ? new Api.InputPeerChannel({ channelId: BigInt(to_chat_id), accessHash: BigInt(to_access_hash) })
      : new Api.InputPeerChat({ chatId: BigInt(Math.abs(to_chat_id)) });

    const result = await client.invoke(
      new Api.messages.ForwardMessages({
        fromPeer,
        toPeer,
        id: message_ids,
        randomId: message_ids.map(() => BigInt(Math.floor(Math.random() * 1e15))),
        dropAuthor: drop_author,
      })
    );

    serverStats.successfulRequests++;
    serverStats.lastSuccessfulRequest = new Date().toISOString();

    res.json({
      success: true,
      forwarded: message_ids.length,
      updates: result,
    });
  } catch (error) {
    log('error', 'forwardMessages failed', { error: error.message });
    serverStats.failedRequests++;
    serverStats.lastError = { message: error.message, timestamp: new Date().toISOString() };
    res.status(500).json({ error: error.message, success: false });
  }
});

// ==================== SEND MEDIA (Clone sem forward tag) ====================
app.post('/send-media', verifySecret, async (req, res) => {
  try {
    const { 
      session_string, 
      from_chat_id, 
      to_chat_id, 
      message_id, 
      from_access_hash, 
      to_access_hash,
      user_id,
      phone_number,
      caption 
    } = req.body;
    
    if (!session_string || !from_chat_id || !to_chat_id || !message_id) {
      return res.status(400).json({ error: 'Missing required parameters', success: false });
    }

    const decryptedSession = decrypt(session_string, SERVER_SECRET);
    if (!decryptedSession) {
      return res.status(400).json({ error: 'Invalid session', success: false });
    }

    log('info', 'Sending media', { from: from_chat_id, to: to_chat_id, message_id });

    const identifier = `${user_id}_${phone_number}`;
    const client = await getOrCreateClient(decryptedSession, identifier);

    // Get original message
    let fromPeer;
    if (from_access_hash) {
      fromPeer = new Api.InputPeerChannel({ channelId: BigInt(from_chat_id), accessHash: BigInt(from_access_hash) });
    } else {
      fromPeer = new Api.InputPeerChat({ chatId: BigInt(Math.abs(from_chat_id)) });
    }

    const messages = await client.getMessages(fromPeer, { ids: [message_id] });
    if (!messages.length || !messages[0].media) {
      return res.status(404).json({ error: 'Mensagem ou mídia não encontrada', success: false });
    }

    const originalMessage = messages[0];

    // Prepare destination
    let toPeer;
    if (to_access_hash) {
      toPeer = new Api.InputPeerChannel({ channelId: BigInt(to_chat_id), accessHash: BigInt(to_access_hash) });
    } else {
      toPeer = new Api.InputPeerChat({ chatId: BigInt(Math.abs(to_chat_id)) });
    }

    // Send without forward tag
    const result = await client.sendMessage(toPeer, {
      message: caption !== undefined ? caption : originalMessage.message,
      file: originalMessage.media,
    });

    serverStats.successfulRequests++;
    serverStats.lastSuccessfulRequest = new Date().toISOString();

    res.json({
      success: true,
      sent_message_id: result.id,
    });
  } catch (error) {
    log('error', 'sendMedia failed', { error: error.message });
    serverStats.failedRequests++;
    serverStats.lastError = { message: error.message, timestamp: new Date().toISOString() };
    res.status(500).json({ error: error.message, success: false });
  }
});

// ==================== LOGOUT ====================
app.post('/logout', verifySecret, async (req, res) => {
  try {
    const { session_string, user_id, phone_number } = req.body;
    
    if (session_string) {
      const decryptedSession = decrypt(session_string, SERVER_SECRET);
      if (decryptedSession) {
        try {
          const stringSession = new StringSession(decryptedSession);
          const client = new TelegramClient(stringSession, API_ID, API_HASH, {
            connectionRetries: 1,
          });
          await client.connect();
          await client.invoke(new Api.auth.LogOut());
          await client.disconnect();
        } catch (e) {
          log('warn', 'Logout from Telegram failed', { error: e.message });
        }
      }
    }

    const loginId = `${user_id}_${phone_number}`;
    if (clientPool.has(loginId)) {
      const { client } = clientPool.get(loginId);
      try { await client.disconnect(); } catch {}
      clientPool.delete(loginId);
    }
    if (pendingLogins.has(loginId)) {
      const { client } = pendingLogins.get(loginId);
      try { await client.disconnect(); } catch {}
      pendingLogins.delete(loginId);
    }

    serverStats.successfulRequests++;

    res.json({ success: true, message: 'Logged out' });
  } catch (error) {
    log('error', 'logout failed', { error: error.message });
    res.status(500).json({ error: error.message, success: false });
  }
});

// ==================== START SERVER ====================
app.listen(PORT, () => {
  console.log(`
╔═══════════════════════════════════════════════════════════════════╗
║              MTProto Server v2.0 - ROBUST EDITION                 ║
╠═══════════════════════════════════════════════════════════════════╣
║  Status:   Running on port ${String(PORT).padEnd(5)}                              ║
║  API ID:   ${API_ID ? 'Configured ✓'.padEnd(15) : 'NOT SET ✗'.padEnd(15)}                              ║
║  API Hash: ${API_HASH ? 'Configured ✓'.padEnd(15) : 'NOT SET ✗'.padEnd(15)}                              ║
║  Secret:   ${SERVER_SECRET !== 'change-me-in-production' ? 'Configured ✓'.padEnd(15) : 'DEFAULT ⚠'.padEnd(15)}                              ║
╠═══════════════════════════════════════════════════════════════════╣
║  Endpoints:                                                       ║
║    GET  /health           - Server status & stats                 ║
║    POST /send-code        - Send verification code                ║
║    POST /verify-code      - Verify code and authenticate          ║
║    POST /get-dialogs      - Get groups and channels               ║
║    POST /get-chat-info    - Validate chat by ID                   ║
║    POST /get-history      - Get message history (with filters)    ║
║    POST /forward-messages - Forward messages                      ║
║    POST /send-media       - Clone media (no forward tag)          ║
║    POST /logout           - End session                           ║
╚═══════════════════════════════════════════════════════════════════╝
  `);
});
