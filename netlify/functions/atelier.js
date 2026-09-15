// netlify/functions/atelier.js
// Stockage des dépôts de fiches atelier/SAV (onglet "Dépôt Fiche Atelier / SAV") et de leur
// journal archivé. Le mot de passe utilisé est celui du scope 'atelier' (voir _shared/auth-shared.js) :
// initialisé sur le mot de passe Admin courant au premier accès, puis indépendant dès qu'il
// est changé (changement fait via auth.js, action 'change', scope 'atelier').
//
// Fichiers déposés : stockés temporairement dans Netlify Blobs (store 'toolbox-atelier-files'),
// un par un, jusqu'à ce que la fusion du jour soit lancée. Une fois la fusion terminée et
// téléchargée côté client, les fichiers du jour sont purgés — seul un résumé texte reste
// archivé indéfiniment (store 'toolbox-atelier-archive'), pour pouvoir vérifier plus tard
// qu'une fiche a bien été reçue tel jour.
//
// POST { action:'verify-only', password }                                -> { ok }
// POST { action:'deposit', password, day, batchId, depositor, filename, base64 }
//   -> ajoute un fichier au dépôt en attente du jour                     -> { ok, id }
// GET  ?action=pool&password=...                                        -> { ok, days: { 'YYYY-MM-DD': [ {batchId,depositor,time,files:[{id,filename}]} ] } }
// GET  ?action=file&password=...&id=...                                 -> { ok, filename, base64 }
// POST { action:'purge-and-archive', password, day, summary }
//   -> supprime les fichiers en attente du jour et archive le résumé     -> { ok }
// GET  ?action=search&password=...&job=...                              -> { ok, matches: [ {day, mergedAt} ] }

const crypto = require('crypto');
const { blobStore, hashPw, getStoredHash } = require('./_shared/auth-shared');

// Accepte le mot de passe Operation (scope 'atelier', historique) OU le mot de passe Admin :
// un compte Admin doit pouvoir utiliser l'Atelier sans connaître le mot de passe Operation.
async function checkPassword(authStore, password) {
  const pwHash = hashPw(password);
  const operationHash = await getStoredHash(authStore, 'atelier');
  if (pwHash === operationHash) return true;
  const adminHash = await getStoredHash(authStore, 'admin');
  return pwHash === adminHash;
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

  const authStore = blobStore('toolbox-auth');
  const filesStore = blobStore('toolbox-atelier-files');
  const indexStore = blobStore('toolbox-atelier-index');
  const archiveStore = blobStore('toolbox-atelier-archive');

  const json = (statusCode, obj) => ({
    statusCode,
    headers: { ...cors, 'Content-Type': 'application/json' },
    body: JSON.stringify(obj),
  });

  // -------------------- GET --------------------
  if (event.httpMethod === 'GET') {
    const qs = event.queryStringParameters || {};
    const action = qs.action;

    if (!(await checkPassword(authStore, qs.password))) {
      return json(401, { ok: false, error: 'Mot de passe incorrect.' });
    }

    if (action === 'pool') {
      const days = {};
      const list = await indexStore.list();
      for (const entry of list.blobs || []) {
        const day = entry.key;
        const raw = await indexStore.get(day);
        days[day] = raw ? JSON.parse(raw) : [];
      }
      return json(200, { ok: true, days });
    }

    if (action === 'file') {
      if (!qs.id) return json(400, { ok: false, error: "Paramètre 'id' manquant." });
      const raw = await filesStore.get(qs.id, { type: 'json' });
      if (!raw) return json(404, { ok: false, error: 'Fichier introuvable (déjà fusionné/purgé ?).' });
      return json(200, { ok: true, filename: raw.filename, base64: raw.base64 });
    }

    if (action === 'search') {
      const job = String(qs.job || '').replace(/\D/g, '');
      if (!job) return json(400, { ok: false, error: "Paramètre 'job' manquant." });
      const matches = [];
      const list = await archiveStore.list();
      for (const entry of list.blobs || []) {
        const raw = await archiveStore.get(entry.key, { type: 'json' });
        if (!raw) continue;
        const runs = Array.isArray(raw) ? raw : [raw];
        runs.forEach((run) => {
          if ((run.numericJobs || []).map(String).indexOf(job) >= 0) {
            matches.push({ day: entry.key, mergedAt: run.mergedAt });
          }
        });
      }
      return json(200, { ok: true, matches });
    }

    return json(400, { ok: false, error: 'Action inconnue.' });
  }

  // -------------------- POST --------------------
  if (event.httpMethod === 'POST') {
    let body;
    try {
      body = JSON.parse(event.body || '{}');
    } catch (e) {
      return json(400, { ok: false, error: 'JSON invalide.' });
    }

    if (body.action === 'verify-only') {
      const ok = await checkPassword(authStore, body.password);
      return json(ok ? 200 : 401, { ok });
    }

    if (!(await checkPassword(authStore, body.password))) {
      return json(401, { ok: false, error: 'Mot de passe incorrect.' });
    }

    if (body.action === 'deposit') {
      const { day, batchId, depositor, filename, base64 } = body;
      if (!day || !batchId || !filename || !base64) {
        return json(400, { ok: false, error: 'Champs manquants pour le dépôt.' });
      }
      const id = `${day}__${batchId}__${crypto.randomUUID()}`;
      await filesStore.set(id, JSON.stringify({ filename, base64 }));

      const raw = await indexStore.get(day);
      const batches = raw ? JSON.parse(raw) : [];
      let batch = batches.find((b) => b.batchId === batchId);
      if (!batch) {
        batch = { batchId, depositor: depositor || 'Non renseigné', time: new Date().toISOString(), files: [] };
        batches.push(batch);
      }
      batch.files.push({ id, filename });
      await indexStore.set(day, JSON.stringify(batches));

      return json(200, { ok: true, id });
    }

    if (body.action === 'purge-and-archive') {
      const { day, summary } = body;
      if (!day) return json(400, { ok: false, error: "Paramètre 'day' manquant." });

      const raw = await indexStore.get(day);
      const batches = raw ? JSON.parse(raw) : [];
      for (const batch of batches) {
        for (const f of batch.files) {
          await filesStore.delete(f.id);
        }
      }
      await indexStore.delete(day);

      const existingRaw = await archiveStore.get(day, { type: 'json' });
      const existing = Array.isArray(existingRaw) ? existingRaw : existingRaw ? [existingRaw] : [];
      existing.push({ ...(summary || {}), mergedAt: new Date().toISOString() });
      await archiveStore.set(day, JSON.stringify(existing));

      return json(200, { ok: true });
    }

    return json(400, { ok: false, error: 'Action inconnue.' });
  }

  return json(405, { ok: false, error: 'Méthode non autorisée.' });
};
