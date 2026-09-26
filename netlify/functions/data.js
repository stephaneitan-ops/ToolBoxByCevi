// netlify/functions/data.js
// API générique de stockage clé-valeur pour Tool Box by C·Evidentia.
// GET  /.netlify/functions/data?key=xxx                          -> { value: "..." | null }
// POST /.netlify/functions/data  { key, value, password, scope } -> { ok: true }
// `scope` est optionnel et vaut 'admin' par défaut (rétrocompatible). Les écritures
// faites depuis l'onglet Dépôt Fiche Atelier / SAV utilisent 'atelier' pour être
// vérifiées contre le mot de passe atelier plutôt que le mot de passe Admin.

const { blobStore, checkScopeAuthorized, checkAnyProfileAuthorized } = require('./_shared/auth-shared');

// Ajout / correction d'un SKU manquant (onglet Hauteur Cote B, ouvert à tous les profils connectés,
// et Admin > Catalogues). Action dédiée plutôt que l'écriture générique : le serveur ne modifie
// QU'UNE entrée de 'frames-sku-overrides' à la fois (pas d'écrasement de toute la table par un
// client) et journalise chaque modification (qui / quand / quoi) dans 'frames-sku-overrides-log'.
// Supprimer une correction (SKU vide) reste réservé au niveau Administrateur.
const SKU_OVERRIDES_KEY = 'frames-sku-overrides';
const SKU_LOG_KEY = 'frames-sku-overrides-log';
const SKU_LOG_MAX = 3000;

async function handleSkuOverride(dataStore, body, cors) {
  const json = (code, obj) => ({ statusCode: code, headers: { ...cors, 'Content-Type': 'application/json' }, body: JSON.stringify(obj) });
  const authStore = blobStore('toolbox-auth');
  const key = String(body.key || '').trim();
  const sku = String(body.sku || '').trim();
  const author = String(body.author || '').trim().replace(/\s+/g, ' ');
  const ref = body.ref && typeof body.ref === 'object' ? body.ref : {};
  if (!key || key.length > 400 || key.split('||').length !== 4) return json(400, { error: 'Référence invalide.' });
  if (author.length < 2 || author.length > 60) return json(400, { error: 'Merci d\'indiquer votre nom (2 à 60 caractères).' });
  if (sku.length > 40 || (sku && !/^[A-Za-z0-9._\-\/ ]+$/.test(sku))) return json(400, { error: 'SKU invalide (lettres, chiffres, . _ - / uniquement, 40 caractères max).' });

  if (!(await checkAnyProfileAuthorized(dataStore, authStore, body.password))) {
    return json(401, { error: 'Session expirée ou mot de passe incorrect. Reconnectez-vous.' });
  }
  if (!sku && !(await checkScopeAuthorized(dataStore, authStore, body.password, 'admin'))) {
    return json(403, { error: 'Seul un Administrateur peut supprimer un SKU.' });
  }

  let overrides = {};
  try { overrides = JSON.parse((await dataStore.get(SKU_OVERRIDES_KEY)) || '{}') || {}; } catch (e) { overrides = {}; }
  const previous = overrides[key] || '';
  if (sku) overrides[key] = sku; else delete overrides[key];
  await dataStore.set(SKU_OVERRIDES_KEY, JSON.stringify(overrides));

  let log = [];
  try { log = JSON.parse((await dataStore.get(SKU_LOG_KEY)) || '[]'); } catch (e) { log = []; }
  if (!Array.isArray(log)) log = [];
  const clip = (v) => String(v == null ? '' : v).slice(0, 80);
  log.push({
    at: new Date().toISOString(),
    author,
    profile: clip(body.profile),
    origin: body.origin === 'admin' ? 'admin' : 'coteb',
    key,
    ref: { marque: clip(ref.marque), modele: clip(ref.modele), couleur: clip(ref.couleur), taille: clip(ref.taille) },
    old: previous,
    new: sku,
  });
  if (log.length > SKU_LOG_MAX) log = log.slice(log.length - SKU_LOG_MAX);
  await dataStore.set(SKU_LOG_KEY, JSON.stringify(log));

  return json(200, { ok: true, overrides });
}

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
    if (body.action === 'sku-override') {
      return handleSkuOverride(dataStore, body, cors);
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
