require('dotenv').config();
const express = require('express');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const jwt = require('jsonwebtoken');

const app = express();

// Environment variables
const AUTH_BASE_URL = process.env.AUTH_BASE_URL;  // e.g. "https://auth-abdul.onrender.com"
const FRONT_BASE_URL = process.env.FRONT_BASE_URL; // e.g. "https://dzdubai.webflow.io"
const SESSION_SECRET = process.env.SESSION_SECRET;

// Initialize Passport
app.use(passport.initialize());

// Configure Google OAuth strategy
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: `${AUTH_BASE_URL}/auth/google/callback`
}, (accessToken, refreshToken, profile, done) => {
  done(null, profile);
}));

// 1) Trigger OAuth via popup
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

// 2) OAuth callback: inline HTML to postMessage and close popup
app.get('/auth/google/callback',
  passport.authenticate('google', { session: false, failureRedirect: FRONT_BASE_URL }),
  (req, res) => {
    const user = req.user;
    const payload = {
      id: user.id,
      name: user.displayName,
      email: (user.emails && user.emails[0] && user.emails[0].value) || ''
    };
    const token = jwt.sign(payload, SESSION_SECRET, { expiresIn: '1d' });

    res.send(`<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <title>Connexion réussie</title>
</head>
<body>
  <script>
    // Post token and user to opener and close popup
    const data = { token: '${token}', user: ${JSON.stringify(payload)} };
    window.opener.postMessage(data, '${FRONT_BASE_URL}');
    window.close();
  </script>
</body>
</html>`);
  }
);

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
