// netlify/functions/auth.js
// Vérifie ou change le mot de passe d'une "zone" protégée de Tool Box by C·Evidentia.
// Zones actuelles : 'admin' (onglet Admin) et 'atelier' (onglet Dépôt Fiche Atelier / SAV).
// POST { action: 'verify', password, scope }                -> { ok: true|false }
// POST { action: 'change', oldPassword, newPassword, scope } -> { ok: true } ou { error: "..." }
// `scope` est optionnel et vaut 'admin' par défaut (rétrocompatible avec le code existant,
// qui n'envoie pas encore ce champ).

const { blobStore, hashPw, resolveScope, getStoredHash, SCOPE_KEYS } = require('./_shared/auth-shared');

exports.handler = async (event) => {
  const cors = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };

  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 204, headers: cors, body: '' };
  }
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, headers: cors, body: JSON.stringify({ error: 'Méthode non autorisée.' }) };
  }

  if (!process.env.NETLIFY_BLOBS_TOKEN) {
    return {
      statusCode: 500,
      headers: { ...cors, 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: "Variable d'environnement NETLIFY_BLOBS_TOKEN manquante sur le site Netlify." }),
    };
  }

  let body;
  try {
    body = JSON.parse(event.body || '{}');
  } catch (e) {
    return { statusCode: 400, headers: cors, body: JSON.stringify({ error: 'JSON invalide.' }) };
  }

  const scope = resolveScope(body.scope);
  const authStore = blobStore('toolbox-auth');
  const storedHash = await getStoredHash(authStore, scope);

  if (body.action === 'verify') {
    const ok = hashPw(body.password) === storedHash;
    return {
      statusCode: ok ? 200 : 401,
      headers: { ...cors, 'Content-Type': 'application/json' },
      body: JSON.stringify({ ok }),
    };
  }

  if (body.action === 'change') {
    if (hashPw(body.oldPassword) !== storedHash) {
      return {
        statusCode: 401,
        headers: { ...cors, 'Content-Type': 'application/json' },
        body: JSON.stringify({ ok: false, error: 'Ancien mot de passe incorrect.' }),
      };
    }
    if (!body.newPassword || String(body.newPassword).length < 6) {
      return {
        statusCode: 400,
        headers: { ...cors, 'Content-Type': 'application/json' },
        body: JSON.stringify({ ok: false, error: 'Le nouveau mot de passe doit contenir au moins 6 caractères.' }),
      };
    }
    await authStore.set(SCOPE_KEYS[scope], hashPw(body.newPassword));
    return {
      statusCode: 200,
      headers: { ...cors, 'Content-Type': 'application/json' },
      body: JSON.stringify({ ok: true }),
    };
  }

  return { statusCode: 400, headers: cors, body: JSON.stringify({ error: 'Action inconnue.' }) };
};
