// netlify/functions/atelier.js
// Onglet Atelier > "Fusion FT" (V3.10).
//
// Les fiches atelier (PDF Cosium, donnees de sante) ne transitent JAMAIS par ce serveur :
// elles sont deposees par les admins dans la bibliotheque SharePoint "Fiches Atelier",
// puis lues, triees et fusionnees uniquement dans le navigateur du poste qui imprime.
//
// Ce serveur ne stocke que l'HISTORIQUE des lots valides, sans aucune donnee patient :
//   { id, date, jourDepot, lot, pages, jobs:[...], entries:[{ job, hash }] }
//   - job  : numero de job (ex. "J1011000300"), "FORMULAIRE" ou null
//   - hash : empreinte SHA-256 tronquee du texte de la page (sert a reperer une fiche deja
//            imprimee un autre jour ; ne permet pas de retrouver le contenu)
// Aucun nom de fichier, aucun nom de client.
//
// Store 'toolbox-atelier-history' : un blob par mois ('YYYY-MM') = tableau de lots.
// Historique conserve 12 mois.
//
// GET  ?action=history&password=...          -> { ok, lots: [...] }   (12 derniers mois)
// GET  ?action=search&password=...&job=...   -> { ok, matches: [ {day, mergedAt} ] }  (ancien journal, avant V3.10)
// POST { action:'verify-only', password }    -> { ok }
// POST { action:'record-lot', password, lot } -> { ok }
// POST { action:'purge-legacy', password }   -> { ok, deleted }  supprime les PDF encore stockes
//                                               par l'ancien sous-onglet "Depot Atelier / SAV"

const { blobStore, checkScopeAuthorized } = require('./_shared/auth-shared');

const HISTORY_MONTHS = 12;

async function checkPassword(dataStore, authStore, password) {
  return checkScopeAuthorized(dataStore, authStore, password, 'atelier');
}

function monthKey(d) {
  return d.getUTCFullYear() + '-' + String(d.getUTCMonth() + 1).padStart(2, '0');
}

function recentMonthKeys(n) {
  const keys = [];
  const d = new Date();
  d.setUTCDate(1);
  for (let i = 0; i < n; i++) {
    keys.push(monthKey(d));
    d.setUTCMonth(d.getUTCMonth() - 1);
  }
  return keys;
}

// Nettoyage defensif : seuls les champs attendus, aucun champ libre (pas de nom de fichier).
function sanitizeLot(lot) {
  const s = (v, max) => String(v == null ? '' : v).slice(0, max);
  const entries = Array.isArray(lot.entries) ? lot.entries.slice(0, 5000) : [];
  return {
    id: s(lot.id, 64),
    date: new Date(lot.date || Date.now()).toISOString(),
    jourDepot: /^\d{4}-\d{2}-\d{2}$/.test(lot.jourDepot || '') ? lot.jourDepot : null,
    lot: s(lot.lot, 80),
    pages: Number(lot.pages) || entries.length,
    jobs: (Array.isArray(lot.jobs) ? lot.jobs : []).map((j) => s(j, 20)).filter((j) => /^J\d{6,12}$/.test(j)).slice(0, 5000),
    entries: entries.map((e) => ({
      job: e && e.job && (/^J\d{6,12}$/.test(e.job) || e.job === 'FORMULAIRE') ? e.job : null,
      hash: /^[0-9a-f]{8,64}$/.test((e && e.hash) || '') ? e.hash : null,
    })),
  };
}

exports.handler = async (event) => {
  const cors = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };
  if (event.httpMethod === 'OPTIONS') return { statusCode: 204, headers: cors, body: '' };

  const json = (statusCode, obj) => ({
    statusCode,
    headers: { ...cors, 'Content-Type': 'application/json' },
    body: JSON.stringify(obj),
  });

  if (!process.env.NETLIFY_BLOBS_TOKEN) {
    return json(500, { error: "Variable d'environnement NETLIFY_BLOBS_TOKEN manquante sur le site Netlify." });
  }

  const authStore = blobStore('toolbox-auth');
  const dataStore = blobStore('toolbox-data');
  const historyStore = blobStore('toolbox-atelier-history');
  const archiveStore = blobStore('toolbox-atelier-archive'); // ancien journal (lecture seule)

  // -------------------- GET --------------------
  if (event.httpMethod === 'GET') {
    const qs = event.queryStringParameters || {};
    if (!(await checkPassword(dataStore, authStore, qs.password))) {
      return json(401, { ok: false, error: 'Mot de passe incorrect.' });
    }

    if (qs.action === 'history') {
      const lots = [];
      for (const key of recentMonthKeys(HISTORY_MONTHS + 1)) {
        const raw = await historyStore.get(key, { type: 'json' });
        if (Array.isArray(raw)) lots.push(...raw);
      }
      const limit = Date.now() - HISTORY_MONTHS * 31 * 864e5;
      return json(200, { ok: true, lots: lots.filter((l) => new Date(l.date).getTime() >= limit) });
    }

    if (qs.action === 'search') {
      const job = String(qs.job || '').replace(/\D/g, '');
      if (!job) return json(400, { ok: false, error: "Parametre 'job' manquant." });
      const matches = [];
      const list = await archiveStore.list();
      for (const entry of list.blobs || []) {
        const raw = await archiveStore.get(entry.key, { type: 'json' });
        if (!raw) continue;
        (Array.isArray(raw) ? raw : [raw]).forEach((run) => {
          if ((run.numericJobs || []).map(String).indexOf(job) >= 0) matches.push({ day: entry.key, mergedAt: run.mergedAt });
        });
      }
      return json(200, { ok: true, matches });
    }

    return json(400, { ok: false, error: 'Action inconnue.' });
  }

  // -------------------- POST --------------------
  if (event.httpMethod === 'POST') {
    let body;
    try { body = JSON.parse(event.body || '{}'); } catch (e) { return json(400, { ok: false, error: 'JSON invalide.' }); }

    if (body.action === 'verify-only') {
      const ok = await checkPassword(dataStore, authStore, body.password);
      return json(ok ? 200 : 401, { ok });
    }

    if (!(await checkPassword(dataStore, authStore, body.password))) {
      return json(401, { ok: false, error: 'Mot de passe incorrect.' });
    }

    if (body.action === 'record-lot') {
      if (!body.lot || typeof body.lot !== 'object') return json(400, { ok: false, error: "Parametre 'lot' manquant." });
      const lot = sanitizeLot(body.lot);
      const key = monthKey(new Date(lot.date));
      const existing = (await historyStore.get(key, { type: 'json' })) || [];
      if (!existing.some((l) => l.id && l.id === lot.id)) existing.push(lot); // idempotent
      await historyStore.set(key, JSON.stringify(existing));
      // Purge des mois trop anciens
      const keep = new Set(recentMonthKeys(HISTORY_MONTHS + 1));
      const list = await historyStore.list();
      for (const b of list.blobs || []) { if (!keep.has(b.key)) await historyStore.delete(b.key); }
      return json(200, { ok: true });
    }

    if (body.action === 'purge-legacy') {
      let deleted = 0;
      for (const name of ['toolbox-atelier-files', 'toolbox-atelier-index']) {
        const store = blobStore(name);
        const list = await store.list();
        for (const b of list.blobs || []) { await store.delete(b.key); deleted++; }
      }
      return json(200, { ok: true, deleted });
    }

    return json(400, { ok: false, error: 'Action inconnue.' });
  }

  return json(405, { ok: false, error: 'Methode non autorisee.' });
};
