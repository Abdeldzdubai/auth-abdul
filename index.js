// index.js
require('dotenv').config();
const express   = require('express');
const path      = require('path');
const passport  = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const jwt       = require('jsonwebtoken');

const app = express();

// Pour parser le body JSON (nécessaire si vous utilisez One-Tap en POST)
app.use(express.json());

// 1) Initialisation de Passport
app.use(passport.initialize());

// 2) Stratégie Google OAuth pour le popup
passport.use(new GoogleStrategy({
  clientID:     process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL:  process.env.AUTH_CALLBACK_URL  // ex. https://auth-abdul.onrender.com/auth/google/callback
}, (accessToken, refreshToken, profile, done) => {
  const user = {
    id:          profile.id,
    displayName: profile.displayName,
    emails:      profile.emails,
    photos:      profile.photos
  };
  done(null, user);
}));

// 3) Route d’authentification initiale (popup)
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile','email'] })
);

// 4) Callback OAuth : on envoie un HTML inline qui postMessage + ferme le popup
app.get('/auth/google/callback',
  passport.authenticate('google', { session: false, failureRedirect: '/login' }),
  (req, res) => {
    const user = req.user;
    const payload = {
      id:      user.id,
      name:    user.displayName,
      email:   user.emails[0].value,
      picture: user.photos[0].value
    };
    const token = jwt.sign(payload, process.env.SESSION_SECRET, { expiresIn: '1d' });

    res.send(\`
      <!DOCTYPE html>
      <html lang="fr">
      <head><meta charset="utf-8"><title>Connexion réussie</title></head>
      <body>
        <script>
          // Envoie le token et le profil à la fenêtre parente
          window.opener.postMessage(
            {
              token: '\${token}',
              user: \${JSON.stringify(payload)}
            },
            '\${process.env.FRONT_BASE_URL}'  // ex. https://dzdubai.webflow.io
          );
          // Ferme immédiatement la popup
          window.close();
        </script>
      </body>
      </html>
    \`);
  }
);

// 5) Route pour Google One-Tap (à adapter selon votre implémentation)
app.post('/auth/onetap', (req, res) => {
  const { credential } = req.body;
  try {
    const decoded = jwt.verify(credential, process.env.GOOGLE_CLIENT_SECRET);
    res.json({ user: decoded });
  } catch (err) {
    res.status(401).json({ error: 'One-Tap invalide' });
  }
});

// 6) Static files et fallback SPA
app.use(express.static('public'));
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// 7) Démarrage
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Serveur démarré sur le port ${PORT}`);
});
