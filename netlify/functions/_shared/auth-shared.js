// netlify/functions/_shared/auth-shared.js
// Utilitaires communs de mot de passe/stockage, partagés par auth.js, data.js et atelier.js.
// Ce fichier n'exporte pas de `handler` : Netlify ne le traite donc pas comme une fonction
// à part entière, il est simplement importé (bundlé) par les fonctions qui en ont besoin.

const { getStore } = require('@netlify/blobs');
const crypto = require('crypto');

const DEFAULT_PASSWORD = 'Teamops2026'; // mot de passe Admin initial
const SITE_ID = '1073646c-ef38-4e99-b77a-2a7aaa928b25'; // Project ID Netlify (toolboxbycevidentia, ex-lapdmbycevidentia)

// Clé de stockage Blobs utilisée pour chaque zone protégée. Garder ces noms identiques
// partout : c'est ce qui permet à auth.js (changement de mot de passe) et à data.js /
// atelier.js (vérification) de toujours lire/écrire le même hash.
const SCOPE_KEYS = {
  admin: 'password-hash',
  atelier: 'password-hash:atelier',
  // 'operation' remplace 'atelier' côté rôles (Opticien / Operation / Admin) : même hash
  // stocké, pour que le mot de passe existant (Teamops2026 par défaut) reste valable.
  operation: 'password-hash:atelier',
};

// Configuration manuelle du store : nécessaire dans certains contextes de déploiement où
// Netlify n'injecte pas automatiquement le contexte Blobs. Le jeton est lu depuis une
// variable d'environnement (Project configuration -> Environment variables -> NETLIFY_BLOBS_TOKEN).
function blobStore(name) {
  return getStore({
    name,
    siteID: SITE_ID,
    token: process.env.NETLIFY_BLOBS_TOKEN,
  });
}

function hashPw(pw) {
  return crypto.createHash('sha256').update(String(pw || '')).digest('hex');
}

function resolveScope(scope) {
  return SCOPE_KEYS[scope] ? scope : 'admin';
}

// Renvoie le hash stocké pour une zone. Si rien n'existe encore en base, chaque zone
// ('admin' et 'atelier') est initialisée indépendamment au même mot de passe par défaut
// (Teamops2026) — plus de copie du mot de passe Admin courant, pour que le mot de passe
// Atelier de départ reste toujours Teamops2026 même si l'Admin a déjà été changé.
async function getStoredHash(authStore, scope) {
  const s = resolveScope(scope);
  const key = SCOPE_KEYS[s];
  let hash = await authStore.get(key);
  if (!hash) {
    hash = hashPw(DEFAULT_PASSWORD);
    await authStore.set(key, hash);
  }
  return hash;
}

// ---- Profils personnalisés (Admin > Profils) : mot de passe propre par profil ----
// Un profil a son propre mot de passe, indépendant des mots de passe partagés Operation/Admin
// (voir index.html, Admin > Profils). Stocké sous une clé dédiée par profil, jamais dans
// SCOPE_KEYS (liste fixe des 3 zones historiques). La liste des profils elle-même (id, nom,
// niveau d'accès 'baseRole', onglets visibles) vit dans le store 'toolbox-data', clé
// 'app-custom-profiles' — géré par data.js / index.html, pas ici.
function profilePasswordKey(id) {
  const safeId = String(id || '').replace(/[^a-z0-9-]/gi, '');
  return `password-hash:profile:${safeId}`;
}

function isProfileScope(scope) {
  return typeof scope === 'string' && scope.indexOf('profile:') === 0;
}

function profileIdFromScope(scope) {
  return scope.slice('profile:'.length);
}

// Hiérarchie des 3 niveaux d'accès (utilisés comme 'baseRole' des profils, voir Admin >
// Profils dans index.html) et niveau minimum requis par zone protégée. 'opticien' est le
// niveau le plus faible (onglets de base, aucune écriture serveur ne le requiert jamais) —
// il ne doit JAMAIS pouvoir autoriser une zone 'operation'/'atelier'/'admin'.
const ROLE_LEVELS = { opticien: 0, operation: 1, admin: 2 };
const SCOPE_MIN_LEVEL = { admin: 2, operation: 1, atelier: 1, opticien: 0 };

// Renvoie le hash du mot de passe propre d'un profil. Pour les 2 profils de base historiques
// ('operation' et 'admin', anciennement les seuls rôles protégés par mot de passe), tant
// qu'aucun mot de passe propre n'a été fixé depuis Admin > Profils, on retombe sur l'ancien
// mot de passe partagé (zones historiques 'atelier'/'admin') — pour ne jamais bloquer l'accès
// juste après le déploiement de cette mise à jour. 'opticien' est nouveau (pas d'historique) :
// initialisé directement sur Vision2026, comme les autres zones s'auto-initialisent.
async function getProfileStoredHash(authStore, id) {
  const own = await authStore.get(profilePasswordKey(id));
  if (own) return own;
  if (id === 'operation') return getStoredHash(authStore, 'atelier');
  if (id === 'admin') return getStoredHash(authStore, 'admin');
  if (id === 'opticien') {
    const hash = hashPw('Vision2026');
    await authStore.set(profilePasswordKey(id), hash);
    return hash;
  }
  return null; // profil personnalisé sans mot de passe encore fixé : ne peut pas encore se connecter
}

// Un profil personnalisé est habilité pour une zone donnée si son niveau d'accès ('baseRole')
// est au moins celui requis par cette zone (voir SCOPE_MIN_LEVEL) — jamais l'inverse.
async function isCustomProfileAuthorized(dataStore, authStore, pwHash, requiredScope) {
  let profiles = [];
  try {
    const raw = await dataStore.get('app-custom-profiles');
    profiles = raw ? JSON.parse(raw) : [];
  } catch (e) { profiles = []; }
  if (!Array.isArray(profiles)) return false;
  const minLevel = SCOPE_MIN_LEVEL[requiredScope] !== undefined ? SCOPE_MIN_LEVEL[requiredScope] : 2;
  for (const p of profiles) {
    if (!p || !p.id || !p.baseRole) continue;
    const level = ROLE_LEVELS[p.baseRole];
    if (level === undefined || level < minLevel) continue;
    const hash = await getProfileStoredHash(authStore, p.id);
    if (hash && hash === pwHash) return true;
  }
  return false;
}

// Vérification complète utilisée par data.js et atelier.js pour autoriser une écriture sur une
// zone donnée : le mot de passe propre de la zone, le mot de passe Admin (toujours accepté en
// plus, sauf sur la zone 'admin' où c'est déjà le cas), ou le mot de passe propre d'un profil
// personnalisé habilité (voir Admin > Profils).
async function checkScopeAuthorized(dataStore, authStore, password, scope) {
  const pwHash = hashPw(password);
  const resolved = resolveScope(scope);
  const storedHash = await getStoredHash(authStore, resolved);
  if (pwHash === storedHash) return true;
  if (resolved !== 'admin') {
    const adminHash = await getStoredHash(authStore, 'admin');
    if (pwHash === adminHash) return true;
  }
  return isCustomProfileAuthorized(dataStore, authStore, pwHash, resolved);
}

// Vérifie qu'un mot de passe correspond à N'IMPORTE QUEL profil connecté (Opticien compris).
// Utilisé uniquement pour les rares écritures ouvertes à tous les profils (ex. ajout d'un SKU
// manquant depuis l'onglet Hauteur Cote B) — ces écritures passent par une action serveur
// dédiée et limitée (voir data.js, action 'sku-override'), jamais par l'écriture générique.
async function checkAnyProfileAuthorized(dataStore, authStore, password) {
  if (!password) return false;
  const pwHash = hashPw(password);
  for (const id of ['opticien', 'operation', 'admin']) {
    const h = await getProfileStoredHash(authStore, id);
    if (h && h === pwHash) return true;
  }
  if (await checkScopeAuthorized(dataStore, authStore, password, 'operation')) return true;
  return isCustomProfileAuthorized(dataStore, authStore, pwHash, 'opticien');
}

module.exports = {
  checkAnyProfileAuthorized,
  blobStore, hashPw, resolveScope, getStoredHash, SCOPE_KEYS, DEFAULT_PASSWORD, SITE_ID,
  profilePasswordKey, isProfileScope, profileIdFromScope, isCustomProfileAuthorized, checkScopeAuthorized,
  getProfileStoredHash, ROLE_LEVELS, SCOPE_MIN_LEVEL,
};
