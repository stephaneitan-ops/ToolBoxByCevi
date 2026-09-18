// netlify/functions/data.js
// API générique de stockage clé-valeur pour Tool Box by C·Evidentia.
// GET  /.netlify/functions/data?key=xxx                          -> { value: "..." | null }
// POST /.netlify/functions/data  { key, value, password, scope } -> { ok: true }
// `scope` est optionnel et vaut 'admin' par défaut (rétrocompatible). Les écritures
// faites depuis l'onglet Dépôt Fiche Atelier / SAV utilisent 'atelier' pour être
// vérifiées contre le mot de passe atelier plutôt que le mot de passe Admin.

const { blobStore, checkScopeAuthorized } = require('./_shared/auth-shared');

exports.handler = async (event) => {
  const cors = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };

  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 204, headers: cors, body: '' };
  }

  if (!process.env.NETLIFY_BLOBS_TOKEN) {
    return {
      statusCode: 500,
      headers: { ...cors, 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: "Variable d'environnement NETLIFY_BLOBS_TOKEN manquante sur le site Netlify." }),
    };
  }

  const dataStore = blobStore('toolbox-data');

  if (event.httpMethod === 'GET') {
    const key = event.queryStringParameters && event.queryStringParameters.key;
    if (!key) {
      return { statusCode: 400, headers: cors, body: JSON.stringify({ error: "Paramètre 'key' manquant." }) };
    }
    const value = await dataStore.get(key);
    return {
      statusCode: 200,
      headers: { ...cors, 'Content-Type': 'application/json' },
      body: JSON.stringify({ value: value === undefined ? null : value }),
    };
  }

  if (event.httpMethod === 'POST') {
    let body;
    try {
      body = JSON.parse(event.body || '{}');
    } catch (e) {
      return { statusCode: 400, headers: cors, body: JSON.stringify({ error: 'JSON invalide.' }) };
    }
    const { key, value, password, scope } = body;
    if (!key) {
      return { statusCode: 400, headers: cors, body: JSON.stringify({ error: "Paramètre 'key' manquant." }) };
    }

    // Un mot de passe Admin est toujours accepté, même sur une zone à privilège moindre
    // (ex. scope 'operation') : un compte Admin n'a pas besoin de connaître le mot de passe
    // Operation pour agir dessus. L'inverse n'est pas vrai. Le mot de passe propre d'un profil
    // personnalisé habilité (Admin > Profils) est également accepté — voir checkScopeAuthorized.
    const authStore = blobStore('toolbox-auth');
    const authorized = await checkScopeAuthorized(dataStore, authStore, password, scope);
    if (!authorized) {
      return { statusCode: 401, headers: cors, body: JSON.stringify({ error: 'Mot de passe incorrect.' }) };
    }

    await dataStore.set(key, typeof value === 'string' ? value : JSON.stringify(value));
    return { statusCode: 200, headers: { ...cors, 'Content-Type': 'application/json' }, body: JSON.stringify({ ok: true }) };
  }

  return { statusCode: 405, headers: cors, body: JSON.stringify({ error: 'Méthode non autorisée.' }) };
};
