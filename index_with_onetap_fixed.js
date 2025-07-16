
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const { OAuth2Client } = require('google-auth-library');
const cors = require('cors');

const app = express();

app.use(cors({ origin: 'https://dzdubai.webflow.io', credentials: true }));
app.use(express.json());

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    sameSite: 'None',
    secure: true,
    maxAge: 24 * 60 * 60 * 1000
  }
}));

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.BASE_URL + "/auth/google/callback"
}, (accessToken, refreshToken, profile, done) => {
  return done(null, profile);
}));

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/' }),
  (req, res) => {
    const user = req.user;
    const name = encodeURIComponent(user.displayName);
    const email = encodeURIComponent(user.emails[0].value);
    const picture = encodeURIComponent(user.photos[0].value);
    res.redirect(`${process.env.BASE_URL}/auth/success?name=${name}&email=${email}&picture=${picture}`);
  }
);

app.get('/me', (req, res) => {
  if (!req.user) return res.status(401).send('Non connecté');
  res.send(req.user);
});

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
app.post('/auth/onetap', async (req, res) => {
  const token = req.body.credential;

  try {
    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();
    const user = {
      name: payload.name,
      email: payload.email,
      picture: payload.picture,
      email_verified: payload.email_verified,
    };

    console.log("Utilisateur connecté via One Tap :", user);
    res.json({ success: true, user });
  } catch (err) {
    console.error("Erreur One Tap :", err);
    res.status(401).json({ success: false, message: "Token invalide" });
  }
});

app.get("/user", (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: "Non connecté" });
  }

  res.json({
    name: req.user.displayName || req.user.name || "",
    email: req.user.emails?.[0]?.value || req.user.email || "",
    picture: req.user.photos?.[0]?.value || req.user.picture || ""
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Serveur en écoute sur le port ${PORT}`));
