// Fichier index.js complet avec les clés intégrées

const express = require('express');
const path = require('path');
const session = require('express-session');
const cors = require('cors');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const { OAuth2Client } = require('google-auth-library');

const app = express();

// Constantes de configuration (intégrées)
const GOOGLE_CLIENT_ID = "377917242237-m4l494os8r0dttgf93e164q9gd12fuea.apps.googleusercontent.com";
const GOOGLE_CLIENT_SECRET = "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";
const SESSION_SECRET = "Abdelnour71!";
const BASE_URL = "https://auth-abdul.onrender.com";

// 1) CORS : autorise Webflow à appeler ton backend
app.use(cors({
  origin: 'https://dzdubai.webflow.io',
  credentials: true
}));

// 2) Pour parser les JSON bodies (One Tap et autres)
app.use(express.json());

// 3) Sessions Express
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    sameSite: 'None',
    secure: true,
    maxAge: 24 * 60 * 60 * 1000
  }
}));

// 4) Passport.js pour Google OAuth classique
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

passport.use(new GoogleStrategy({
    clientID: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    callbackURL: BASE_URL + '/auth/google/callback'
  },
  (accessToken, refreshToken, profile, done) => {
    return done(null, profile);
  }
));

// Routes OAuth2 “classique”
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/' }),
  (req, res) => {
    const user = req.user;
    const name    = encodeURIComponent(user.displayName);
    const email   = encodeURIComponent(user.emails[0].value);
    const picture = encodeURIComponent(user.photos[0].value);
    res.redirect(`${BASE_URL}/auth/success?name=${name}&email=${email}&picture=${picture}`);
  }
);

// Route /auth/success pour servir success.html
app.get('/auth/success', (req, res) => {
  res.sendFile(path.join(__dirname, 'success.html'));
});

// Route One Tap
const oneTapClient = new OAuth2Client(GOOGLE_CLIENT_ID);
app.post('/auth/onetap', async (req, res) => {
  try {
    const ticket = await oneTapClient.verifyIdToken({
      idToken: req.body.credential,
      audience: GOOGLE_CLIENT_ID
    });
    const p = ticket.getPayload();
    const user = {
      name: p.name,
      email: p.email,
      picture: p.picture,
      email_verified: p.email_verified
    };
    console.log('One Tap user:', user);
    return res.json({ success: true, user });
  } catch (err) {
    console.error('One Tap error:', err);
    return res.status(401).json({ success: false, message: 'Token invalide' });
  }
});

// Route /user
app.get('/user', (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Non connecté' });
  }
  res.json({
    name:    req.user.displayName || '',
    email:   req.user.emails?.[0]?.value || '',
    picture: req.user.photos?.[0]?.value || ''
  });
});

// Optionnel /me pour compatibilité
app.get('/me', (req, res) => {
  if (!req.user) return res.status(401).send('Non connecté');
  res.send(req.user);
});

// Démarrage du serveur
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Serveur en écoute sur le port ${PORT}`));
