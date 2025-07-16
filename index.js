require('dotenv').config();
const express = require('express');
const path = require('path');
const session = require('express-session');
const cors = require('cors');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const { OAuth2Client } = require('google-auth-library');

const app = express();

// CORS : autorise Webflow à appeler ton backend
app.use(cors({
  origin: 'https://dzdubai.webflow.io',
  credentials: true
}));

// Parser JSON
app.use(express.json());

// Sessions Express
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { sameSite: 'None', secure: true, maxAge: 24 * 60 * 60 * 1000 }
}));

// Passport pour Google OAuth2 classique
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

passport.use(new GoogleStrategy({
  clientID:     process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL:  process.env.BASE_URL + '/auth/google/callback'
}, (accessToken, refreshToken, profile, done) => {
  done(null, profile);
}));

// Route : démarrer OAuth2 avec popup Google
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

// Route : callback Google OAuth2
app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/' }),
  (req, res) => {
    const user = req.user;
    const q = encodeURIComponent;
    const redirectUrl = `${process.env.BASE_URL}/auth/success?` +
      `name=${q(user.displayName)}&email=${q(user.emails[0].value)}&picture=${q(user.photos[0].value)}`;
    res.redirect(redirectUrl);
  }
);

// Route : servir la page de succès (popup)
app.get('/auth/success', (req, res) => {
  res.sendFile(path.join(__dirname, 'success.html'));
});

// One Tap route
const oneTapClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
app.post('/auth/onetap', async (req, res) => {
  try {
    const ticket = await oneTapClient.verifyIdToken({
      idToken: req.body.credential,
      audience: process.env.GOOGLE_CLIENT_ID
    });
    const p = ticket.getPayload();
    res.json({ success: true, user: {
      name: p.name,
      email: p.email,
      picture: p.picture,
      email_verified: p.email_verified
    }});
  } catch (err) {
    res.status(401).json({ success: false, message: 'Token invalide' });
  }
});

// Route : vérifier la session Passport et renvoyer user
app.get('/user', (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Non connecté' });
  const u = req.user;
  res.json({ name: u.displayName, email: u.emails[0].value, picture: u.photos[0].value });
});

// Optionnel : même chose pour /me
app.get('/me', (req, res) => {
  if (!req.user) return res.status(401).send('Non connecté');
  res.send(req.user);
});

// Démarrage du serveur
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Serveur en écoute sur le port ${PORT}`));
