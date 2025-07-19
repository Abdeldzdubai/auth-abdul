require('dotenv').config();
const express = require('express');
const path = require('path');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

const app = express();

// Base URLs from environment
const AUTH_BASE_URL = process.env.AUTH_BASE_URL;  // e.g. "https://auth-abdul.onrender.com"
const FRONT_BASE_URL = process.env.BASE_URL;      // e.g. "https://dzdubai.webflow.io"

// CORS configuration
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

// Static files (if any)
app.use(express.static(path.join(__dirname, 'public')));

// Initialize Passport
app.use(passport.initialize());

// Google OAuth Strategy for popup flow
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: `${AUTH_BASE_URL}/auth/google/callback`
}, (accessToken, refreshToken, profile, done) => {
  done(null, profile);
}));

// 1) Trigger Google OAuth via popup
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

// 2) OAuth callback: send inline HTML to postMessage and close popup
app.get('/auth/google/callback',
  passport.authenticate('google', { session: false, failureRedirect: `${FRONT_BASE_URL}` }),
  (req, res) => {
    const user = req.user;
    const payload = {
      id:      user.id,
      name:    user.displayName,
      email:   user.emails[0].value,
      picture: user.photos[0].value
    };
    const token = jwt.sign(payload, process.env.SESSION_SECRET, { expiresIn: '1d' });

    // Inline HTML that dynamically determines targetOrigin
    res.send(`<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <title>Connexion réussie</title>
</head>
<body>
  <script>
    // Determine opener origin to ensure correct targetOrigin
    const targetOrigin = window.opener ? window.opener.location.origin : '*';
    // Send token and user info to the opener window
    window.opener.postMessage(
      {
        token: '${token}',
        user: ${JSON.stringify(payload)}
      },
      targetOrigin
    );
    // Close the popup
    window.close();
  </script>
</body>
</html>`);
  }
);

// Google One-Tap route
app.post('/auth/onetap', async (req, res) => {
  try {
    const { credential } = req.body;
    const client = new OAuth2Client(process.env.ONE_TAP_CLIENT_ID);
    const ticket = await client.verifyIdToken({
      idToken: credential,
      audience: process.env.ONE_TAP_CLIENT_ID
    });
    const googlePayload = ticket.getPayload();
    const user = {
      id:      googlePayload.sub,
      name:    googlePayload.name,
      email:   googlePayload.email,
      picture: googlePayload.picture
    };
    const token = jwt.sign(user, process.env.SESSION_SECRET, { expiresIn: '1d' });
    return res.json({ success: true, token, user });
  } catch (err) {
    console.error('OneTap error:', err);
    return res.status(401).json({ success: false, message: 'One Tap authentication failed.' });
  }
});

// Protected user info route
app.get('/user', (req, res) => {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;
  if (!token) {
    return res.status(401).json({ error: 'Non connecté' });
  }
  try {
    const payload = jwt.verify(token, process.env.SESSION_SECRET);
    return res.json({ name: payload.name, email: payload.email, picture: payload.picture });
  } catch (err) {
    return res.status(401).json({ error: 'Token invalide ou expiré' });
  }
});

// Fallback for SPA
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
