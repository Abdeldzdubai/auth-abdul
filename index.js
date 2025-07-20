// index.js
require('dotenv').config();
const express   = require('express');
const path      = require('path');
const cors      = require('cors');
const passport  = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const jwt       = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');
const Airtable  = require('airtable');

const app = express();

// 1) CORS
app.use(cors({
  origin: process.env.BASE_URL,
  credentials: true
}));

// 2) JSON parser
app.use(express.json());
// 3) Static files (optionnel si vous en avez)
app.use(express.static(path.join(__dirname, 'public')));

// 4) Initialize Airtable
Airtable.configure({ apiKey: process.env.AIRTABLE_API_KEY });
const base      = Airtable.base(process.env.AIRTABLE_BASE_ID);
const TABLE     = process.env.AIRTABLE_TABLE_NAME; // ex. "Users"

// 5) Passport setup
app.use(passport.initialize());
passport.use(new GoogleStrategy({
  clientID:     process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL:  `${process.env.AUTH_BASE_URL}/auth/google/callback`
}, (accessToken, refreshToken, profile, done) => done(null, profile)));

// 6) OAuth popup trigger
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile','email'] })
);

// 7) OAuth callback: upsert Airtable by Email only, then postMessage+close
app.get('/auth/google/callback',
  passport.authenticate('google', { session: false, failureRedirect: process.env.BASE_URL }),
  async (req, res) => {
    const p      = req.user;
    const email  = (p.emails[0] && p.emails[0].value) || '';
    const payload = {
      id:      p.id,
      name:    p.displayName,
      email,
      picture: (p.photos[0] && p.photos[0].value) || ''
    };
    // Airtable upsert by Email only
    try {
      console.log('↪️ Upsert Airtable pour', email);
      const [rec] = await base(TABLE)
        .select({ filterByFormula: `{Email}='${email}'`, maxRecords:1 })
        .firstPage();
      if (rec) {
        console.log('↪️ Mise à jour record', rec.id);
        await base(TABLE).update(rec.id, {
          Email:     email,
          fisrtName: p.name?.givenName || '',
          lastName:  p.name?.familyName || ''
        });
      } else {
        console.log('↪️ Création nouveau record');
        await base(TABLE).create({
          Email:     email,
          fisrtName: p.name?.givenName || '',
          lastName:  p.name?.familyName || ''
        });
      }
      console.log('✅ Upsert terminé');
    } catch(err) {
      console.error('Airtable upsert error:', err);
    }

    // JWT generation
    const token = jwt.sign(payload, process.env.SESSION_SECRET, { expiresIn: '1d' });

    // PostMessage + close popup
    res.send(`<!DOCTYPE html><html><body><script>
      window.opener.postMessage(
        { token: '${token}', user: ${JSON.stringify(payload)} },
        '${process.env.BASE_URL}'
      );
      window.close();
    </script></body></html>`);
  }
);

// 8) One‑Tap endpoint (inclut picture)
app.post('/auth/onetap', async (req, res) => {
  try {
    const { credential } = req.body;
    const client = new OAuth2Client(process.env.ONE_TAP_CLIENT_ID);
    const ticket = await client.verifyIdToken({
      idToken: credential,
      audience: process.env.ONE_TAP_CLIENT_ID
    });
    const gp = ticket.getPayload();
    const user = { id: gp.sub, name: gp.name, email: gp.email, picture: gp.picture };
    const token = jwt.sign(user, process.env.SESSION_SECRET, { expiresIn: '1d' });
    res.json({ success: true, token, user });
  } catch (err) {
    console.error('OneTap error:', err);
    res.status(401).json({ success: false, message: 'One Tap authentication failed.' });
  }
});

// 9) Protected /user
app.get('/user', (req, res) => {
  const auth = req.headers.authorization||'';
  const token = auth.startsWith('Bearer ')? auth.slice(7): null;
  if (!token) return res.status(401).json({ error: 'Non connecté' });
  try {
    const p = jwt.verify(token, process.env.SESSION_SECRET);
    res.json({ name: p.name, email: p.email, picture: p.picture });
  } catch {
    res.status(401).json({ error: 'Token invalide ou expiré' });
  }
});

// 10) Remove SPA fallback to avoid missing public/index.html errors

// 11) Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Serveur lancé sur le port ${PORT}`));
