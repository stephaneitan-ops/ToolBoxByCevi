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

// ---- Anomalies atelier (V3.13) ----
// Remontées envoyées par l'extension Atelitool (onglet Anomalies) depuis chaque poste.
// Elles contiennent des noms de clients : stockées sous une clé PRIVÉE (jamais servie par le
// GET public ci-dessous) et lues / supprimées uniquement avec le mot de passe Operation ou Admin.
const ANOMALIES_KEY = 'anomalies-records';
const ANOMALIES_MAX = 20000;
const isPrivateKey = (k) => /^anomalies/i.test(String(k || ''));

function cleanAnomalie(r) {
  const clip = (v, n) => String(v == null ? '' : v).replace(/\s+/g, ' ').trim().slice(0, n);
  if (!r || typeof r !== 'object') return null;
  const id = clip(r.id, 60);
  const ts = Number(r.ts);
  if (!id || !isFinite(ts)) return null;
  const opticien = clip(r.opticien || (Array.isArray(r.opticiens) && r.opticiens.length ? r.opticiens[r.opticiens.length - 1] : ''), 80);
  return {
    id, ts,
    job: clip(r.job, 30).toUpperCase(),
    commande: clip(r.commande, 30),
    client: clip(r.client, 120),
    opticien,
    problemes: (Array.isArray(r.problemes) ? r.problemes : []).map(x => clip(x, 120)).filter(Boolean).slice(0, 20),
    commentaire: clip(r.commentaire, 500),
    poste: clip(r.poste, 80),
    recu: Date.now(),
  };
}

async function readAnomalies(dataStore) {
  try { const o = JSON.parse((await dataStore.get(ANOMALIES_KEY)) || '{}'); return o && typeof o === 'object' && !Array.isArray(o) ? o : {}; }
  catch (e) { return {}; }
}

async function handleAnomalies(dataStore, body, cors) {
  const json = (code, obj) => ({ statusCode: code, headers: { ...cors, 'Content-Type': 'application/json' }, body: JSON.stringify(obj) });
  const authStore = blobStore('toolbox-auth');
  if (!(await checkScopeAuthorized(dataStore, authStore, body.password, 'operation'))) {
    return json(401, { error: 'Mot de passe incorrect.' });
  }
  const all = await readAnomalies(dataStore);

  if (body.action === 'anomalies-list') {
    return json(200, { ok: true, records: Object.values(all).sort((a, b) => b.ts - a.ts) });
  }

  // anomalies-push (extension) et anomalies-delete (onglet Tool Box)
  const ids = [], deleted = [];
  (Array.isArray(body.records) ? body.records : []).slice(0, 500).forEach(r => {
    const c = cleanAnomalie(r);
    if (!c) return;
    if (all[c.id]) c.recu = all[c.id].recu || c.recu;
    all[c.id] = c;
    ids.push(c.id);
  });
  const aSupprimer = Array.isArray(body.deletes) ? body.deletes : (Array.isArray(body.ids) ? body.ids : []);
  aSupprimer.slice(0, 1000).forEach(id => {
    id = String(id || '');
    if (all[id]) delete all[id];
    deleted.push(id);   // idempotent : une remontée déjà absente compte comme supprimée
  });
  const keys = Object.keys(all);
  if (keys.length > ANOMALIES_MAX) {
    keys.sort((a, b) => all[a].ts - all[b].ts).slice(0, keys.length - ANOMALIES_MAX).forEach(k => delete all[k]);
  }
  await dataStore.set(ANOMALIES_KEY, JSON.stringify(all));
  return json(200, { ok: true, ids, deleted });
}

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
    if (isPrivateKey(key)) {
      return { statusCode: 403, headers: cors, body: JSON.stringify({ error: 'Clé privée.' }) };
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
    if (body.action === 'anomalies-push' || body.action === 'anomalies-list' || body.action === 'anomalies-delete') {
      return handleAnomalies(dataStore, body, cors);
    }

    const { key, value, password, scope } = body;
    if (!key) {
      return { statusCode: 400, headers: cors, body: JSON.stringify({ error: "Paramètre 'key' manquant." }) };
    }
    if (isPrivateKey(key)) {
      return { statusCode: 403, headers: cors, body: JSON.stringify({ error: 'Clé privée : passer par les actions anomalies-*.' }) };
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
