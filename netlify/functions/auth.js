// netlify/functions/auth.js
// Vérifie ou change le mot de passe d'une "zone" protégée de Tool Box by C·Evidentia.
// Zones actuelles : 'admin' (onglet Admin) et 'atelier' (onglet Dépôt Fiche Atelier / SAV).
// POST { action: 'verify', password, scope }                -> { ok: true|false }
// POST { action: 'change', oldPassword, newPassword, scope } -> { ok: true } ou { error: "..." }
// `scope` est optionnel et vaut 'admin' par défaut (rétrocompatible avec le code existant,
// qui n'envoie pas encore ce champ).
//
// Profils personnalisés (Admin > Profils, chacun avec son propre mot de passe) :
// POST { action: 'verify', password, scope: 'profile:<id>' }             -> { ok: true|false }
// POST { action: 'set-profile-password', profileId, newPassword, adminPassword }
//   -> { ok: true } ou { error: "..." } — réservé à un identifiant Admin (mot de passe partagé
//   Administrateur, ou mot de passe propre d'un profil de niveau Administrateur) ; utilisé à la
//   fois pour fixer le mot de passe initial à la création d'un profil et pour le changer ensuite.

const {
  blobStore, hashPw, resolveScope, getStoredHash, SCOPE_KEYS,
  profilePasswordKey, isProfileScope, profileIdFromScope, checkScopeAuthorized, getProfileStoredHash,
} = require('./_shared/auth-shared');

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

  const authStore = blobStore('toolbox-auth');
  const dataStore = blobStore('toolbox-data'); // pour retrouver les profils personnalisés (voir checkScopeAuthorized)

  // Connexion à un profil personnalisé : vérifiée contre le mot de passe propre de CE profil
  // uniquement (pas de repli sur le mot de passe Admin/Operation ici, volontairement — un
  // profil a un mot de passe indépendant, voir Admin > Profils dans index.html).
  if (body.action === 'verify' && isProfileScope(body.scope)) {
    const hash = await getProfileStoredHash(authStore, profileIdFromScope(body.scope));
    const ok = !!hash && hashPw(body.password) === hash;
    return {
      statusCode: ok ? 200 : 401,
      headers: { ...cors, 'Content-Type': 'application/json' },
      body: JSON.stringify({ ok }),
    };
  }

  // Fixe ou change le mot de passe d'un profil personnalisé. Réservé à un identifiant Admin
  // (mot de passe Administrateur partagé, ou mot de passe propre d'un profil de niveau
  // Administrateur) — pas besoin de connaître l'ancien mot de passe du profil visé.
  if (body.action === 'set-profile-password') {
    const { profileId, newPassword, adminPassword } = body;
    if (!profileId) {
      return { statusCode: 400, headers: cors, body: JSON.stringify({ ok: false, error: "Paramètre 'profileId' manquant." }) };
    }
    if (!newPassword || String(newPassword).length < 6) {
      return {
        statusCode: 400,
        headers: { ...cors, 'Content-Type': 'application/json' },
        body: JSON.stringify({ ok: false, error: 'Le mot de passe doit contenir au moins 6 caractères.' }),
      };
    }
    const authorized = await checkScopeAuthorized(dataStore, authStore, adminPassword, 'admin');
    if (!authorized) {
      return {
        statusCode: 401,
        headers: { ...cors, 'Content-Type': 'application/json' },
        body: JSON.stringify({ ok: false, error: 'Mot de passe Administrateur incorrect.' }),
      };
    }
    await authStore.set(profilePasswordKey(profileId), hashPw(newPassword));
    return {
      statusCode: 200,
      headers: { ...cors, 'Content-Type': 'application/json' },
      body: JSON.stringify({ ok: true }),
    };
  }

  const scope = resolveScope(body.scope);
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
