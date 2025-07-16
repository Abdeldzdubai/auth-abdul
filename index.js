require('dotenv').config();
const express = require('express');
const path = require('path');
const session = require('express-session');
const cors = require('cors');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const { OAuth2Client } = require('google-auth-library');

const app = express();

// 1) CORS: allow Webflow origin
app.use(cors({
  origin: 'https://dzdubai.webflow.io',
  credentials: true
}));

// 2) JSON parsing
app.use(express.json());

// 3) Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { sameSite: 'None', secure: true, maxAge: 24 * 60 * 60 * 1000 }
}));

// 4) Passport for Google OAuth2 popup
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.BASE_URL + '/auth/google/callback'
  },
  (accessToken, refreshToken, profile, done) => done(null, profile)
));

// Popup authentication routes
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);
app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/' }),
  (req, res) => {
    const u = req.user;
    const q = encodeURIComponent;
    res.redirect(\`\${process.env.BASE_URL}/auth/success?name=\${q(u.displayName)}&email=\${q(u.emails[0].value)}&picture=\${q(u.photos[0].value)}\`);
  }
);

// Serve the success page for popup to postMessage back
app.get('/auth/success', (req, res) => {
  res.sendFile(path.join(__dirname, 'success.html'));
});

// One Tap authentication route
const oneTapClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
app.post('/auth/onetap', async (req, res) => {
  try {
    const ticket = await oneTapClient.verifyIdToken({
      idToken: req.body.credential,
      audience: process.env.GOOGLE_CLIENT_ID
    });
    const p = ticket.getPayload();
    res.json({ success: true, user: { name: p.name, email: p.email, picture: p.picture, email_verified: p.email_verified } });
  } catch {
    res.status(401).json({ success: false, message: 'Token invalide' });
  }
});

// Route to get current logged-in user
app.get('/user', (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Non connecté' });
  const u = req.user;
  res.json({ name: u.displayName, email: u.emails[0].value, picture: u.photos[0].value });
});

// Optional /me route
app.get('/me', (req, res) => {
  if (!req.user) return res.status(401).send('Non connecté');
  res.send(req.user);
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(\`Server listening on port \${PORT}\`));
