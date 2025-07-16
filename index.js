require('dotenv').config();
const express = require('express');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const cookieSession = require('cookie-session');

const app = express();

app.use(cookieSession({
  name: 'session',
  keys: [process.env.SESSION_SECRET],
  maxAge: 24 * 60 * 60 * 1000 // 1 day
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
    res.redirect(`${process.env.BASE_URL}/me?name=${encodeURIComponent(user.displayName)}`);
  }
);

app.get('/me', (req, res) => {
  if (!req.user) return res.status(401).send('Non connecté');
  res.send(req.user);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Serveur en écoute sur le port ${PORT}`));
