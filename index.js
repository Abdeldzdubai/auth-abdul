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
const AUTH_BASE_URL = process.env.AUTH_BASE_URL;  // e.g. https://auth-abdul.onrender.com
const FRONT_BASE_URL = process.env.BASE_URL;      // e.g. https://dzdubai.webflow.io

// CORS configuration to allow calls from Webflow domain
app.use(cors({
  origin: 'https://dzdubai.webflow.io',
  credentials: true
}));
// Handle pre-flight for One Tap route
app.options('/auth/onetap', cors({
  origin: 'https://dzdubai.webflow.io',
  credentials: true
}));

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(passport.initialize());

// Passport Google OAuth 2.0 strategy (popup flow)
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: `${AUTH_BASE_URL}/auth/google/callback`
}, (accessToken, refreshToken, profile, done) => {
  done(null, profile);
}));

// OAuth Popup Routes
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/auth/google/callback',
  passport.authenticate('google', { session: false }),
  (req, res) => {
    const user = req.user;
    const payload = {
      id: user.id,
      name: user.displayName,
      email: user.emails[0].value,
      picture: user.photos[0].value
    };
    const token = jwt.sign(payload, process.env.SESSION_SECRET, { expiresIn: '1d' });
    // Redirect to front with token in query
    res.redirect(`${FRONT_BASE_URL}/auth/success.html?token=${token}`);
  }
);

// Google One Tap Route
app.post('/auth/onetap', async (req, res) => {
  try {
    const { credential } = req.body;
    const client = new OAuth2Client(process.env.ONE_TAP_CLIENT_ID);
    const ticket = await client.verifyIdToken({
      idToken: credential,
      audience: process.env.ONE_TAP_CLIENT_ID
    });
    const p = ticket.getPayload();
    const user = {
      id:      p.sub,
      name:    p.name,
      email:   p.email,
      picture: p.picture
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

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
