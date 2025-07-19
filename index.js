// index.js
require('dotenv').config();
const express = require('express');
const path    = require('path');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const jwt     = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');

const app = express();

// Lecture des variables d’environnement
const AUTH_BASE_URL = process.env.AUTH_BASE_URL;    // ex. https://auth-abdul.onrender.com
const FRONT_BASE_URL = process.env.BASE_URL;       // ex. https://dzdubai.webflow.io
const SESSION_SECRET = process.env.SESSION_SECRET;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const ONE_TAP_CLIENT_ID = process.env.ONE_TAP_CLIENT_ID;

// Pour parser le JSON (One‑Tap)
app.use(express.json());

// Routes statiques si besoin
app.use(express.static(path.join(__dirname, 'public')));

// Initialisation de Passport
app.use(passport.initialize());

// Stratégie OAuth Google pour le popup
passport.use(new GoogleStrategy({
  clientID: GOOGLE_CLIENT_ID,
  clientSecret: GOOGLE_CLIENT_SECRET,
  callbackURL: `${AUTH_BASE_URL}/auth/google/callback`
}, (accessToken, refreshToken, profile, done) => {
  // Réduisez ici le profile si vous le souhaitez
  done(null, profile);
}));

// 1) Déclenchement du popup OAuth
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile','email'] })
);

// 2) Callback OAuth : envoi inline du JS pour postMessage + fermeture
app.get('/auth/google/callback',
  passport.authenticate('google', { session: false, failureRedirect: FRONT_BASE_URL }),
  (req, res) => {
    // Génération du payload et du JWT
    const user = req.user;
    const payload = {
      id:      user.id,
      name:    user.displayName,
      email:   (user.emails[0] && user.emails[0].value) || '',
      picture: (user.photos[0] && user.photos[0].value) || ''
    };
    const token = jwt.sign(payload, SESSION_SECRET, { expiresIn: '1d' });

    // On renvoie un mini‑HTML qui poste le message et ferme la popup
    res.send(`<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <title>Connexion réussie</title>
</head>
<body>
  <script>
    // Envoie le token + user à la fenêtre parente
    window.opener.postMessage(
      { token: '${token}', user: ${JSON.stringify(payload)} },
      '${FRONT_BASE_URL}'
    );
    // Ferme la popup
    window.close();
  </script>
</body>
</html>`);
  }
);

// 3) Endpoint Google One‑Tap (inchangé)
app.post('/auth/onetap', async (req, res) => {
  try {
    const { credential } = req.body;
    const client = new OAuth2Client(ONE_TAP_CLIENT_ID);
    const ticket = await client.verifyIdToken({
      idToken: credential,
      audience: ONE_TAP_CLIENT_ID
    });
    const googlePayload = ticket.getPayload();
    const user = {
      id:      googlePayload.sub,
      name:    googlePayload.name,
      email:   googlePayload.email,
      picture: googlePayload.picture
    };
    const token = jwt.sign(user, SESSION_SECRET, { expiresIn: '1d' });
    res.json({ success: true, token, user });
  } catch (err) {
    console.error('OneTap error:', err);
    res.status(401).json({ success: false, message: 'One Tap authentication failed.' });
  }
});

// 4) Route protégée pour vérifier le token
app.get('/user', (req, res) => {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Non connecté' });
  try {
    const payload = jwt.verify(token, SESSION_SECRET);
    res.json({ name: payload.name, email: payload.email, picture: payload.picture });
  } catch {
    res.status(401).json({ error: 'Token invalide ou expiré' });
  }
});

// 5) Fallback SPA
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Démarrage du serveur
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Serveur lancé sur le port ${PORT}`);
});
