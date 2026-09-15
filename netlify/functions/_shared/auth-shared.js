// netlify/functions/_shared/auth-shared.js
// Utilitaires communs de mot de passe/stockage, partagés par auth.js, data.js et atelier.js.
// Ce fichier n'exporte pas de `handler` : Netlify ne le traite donc pas comme une fonction
// à part entière, il est simplement importé (bundlé) par les fonctions qui en ont besoin.

const { getStore } = require('@netlify/blobs');
const crypto = require('crypto');

const DEFAULT_PASSWORD = 'Teamops2026'; // mot de passe Admin initial
const SITE_ID = '1073646c-ef38-4e99-b77a-2a7aaa928b25'; // Project ID Netlify (lapdmbycevidentia)

// Clé de stockage Blobs utilisée pour chaque zone protégée. Garder ces noms identiques
// partout : c'est ce qui permet à auth.js (changement de mot de passe) et à data.js /
// atelier.js (vérification) de toujours lire/écrire le même hash.
const SCOPE_KEYS = {
  admin: 'password-hash',
  atelier: 'password-hash:atelier',
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

module.exports = { blobStore, hashPw, resolveScope, getStoredHash, SCOPE_KEYS, DEFAULT_PASSWORD, SITE_ID };
