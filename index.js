require('dotenv').config();
const express = require('express');
const path = require('path');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const { OAuth2Client } = require('google-auth-library');

const app = express();

// Environment variables
const AUTH_BASE_URL = process.env.AUTH_BASE_URL; // e.g. https://auth-abdul.onrender.com
const FRONT_BASE_URL = process.env.FRONT_BASE_URL; // e.g. https://dzdubai.webflow.io
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const SESSION_SECRET = process.env.SESSION_SECRET;
const ONE_TAP_CLIENT_ID = process.env.ONE_TAP_CLIENT_ID;

// CORS to allow messages from popup and One-Tap
app.use(cors({
  origin: FRONT_BASE_URL,
  credentials: true
}));
app.options('/auth/onetap', cors({
  origin: FRONT_BASE_URL,
  credentials: true
}));

// JSON parser
app.use(express.json());

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// Initialize Passport
app.use(passport.initialize());

// Configure Google OAuth strategy
passport.use(new GoogleStrategy({
  clientID: GOOGLE_CLIENT_ID,
  clientSecret: GOOGLE_CLIENT_SECRET,
  callbackURL: `${AUTH_BASE_URL}/auth/google/callback`
}, (accessToken, refreshToken, profile, done) => {
  done(null, profile);
}));

// 1) OAuth popup trigger
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

// 2) OAuth callback: send inline HTML to postMessage and close popup
app.get('/auth/google/callback',
  passport.authenticate('google', { session: false, failureRedirect: FRONT_BASE_URL }),
  (req, res) => {
    const user = req.user;
    const payload = {
      id:      user.id,
      name:    user.displayName,
      email:   (user.emails[0] && user.emails[0].value) || null,
      picture: (user.photos[0] && user.photos[0].value) || null
    };
    const token = jwt.sign(payload, SESSION_SECRET, { expiresIn: '1d' });
    // Inline JS to post message and close popup
    res.send(`<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <title>Connexion réussie</title>
</head>
<body>
  <script>
    // Determine target origin from opener
    const targetOrigin = window.opener && window.opener.location.origin
      ? window.opener.location.origin
      : '${FRONT_BASE_URL}';
    // Post token and user data to opener
    window.opener.postMessage(
      { token: '${token}', user: ${JSON.stringify(payload)} },
      targetOrigin
    );
    // Close the popup
    window.close();
  </script>
</body>
</html>`);
  }
);

// 3) Google One-Tap endpoint
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

// 4) Protected user info route
app.get('/user', (req, res) => {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;
  if (!token) {
    return res.status(401).json({ error: 'Non connecté' });
  }
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

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
