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

// === CORS global ===
app.use(cors({
  origin: process.env.BASE_URL,  // ex. https://dzdubai.webflow.io
  credentials: true
}));

// JSON parser
app.use(express.json());
// Static files
app.use(express.static(path.join(__dirname, 'public')));

// Initialize Airtable
Airtable.configure({ apiKey: process.env.AIRTABLE_API_KEY });
const base = Airtable.base(process.env.AIRTABLE_BASE_ID);
const TABLE_NAME = process.env.AIRTABLE_TABLE_NAME;

// Passport & Google OAuth setup
app.use(passport.initialize());
passport.use(new GoogleStrategy({
  clientID:     process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL:  `${process.env.AUTH_BASE_URL}/auth/google/callback`
}, (accessToken, refreshToken, profile, done) => {
  done(null, profile);
}));

// 1) Trigger Google OAuth popup
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile','email'] })
);

// 2) OAuth callback: upsert Airtable, then send HTML to postMessage+close
app.get('/auth/google/callback',
  passport.authenticate('google', { session: false, failureRedirect: process.env.BASE_URL }),
  async (req, res) => {
    const profile   = req.user;
    const userID    = profile.id;
    const firstName = profile.name?.givenName || '';
    const lastName  = profile.name?.familyName  || '';
    const email     = (profile.emails[0] && profile.emails[0].value) || '';
    const picture   = (profile.photos[0] && profile.photos[0].value) || '';

    // --- Airtable upsert ---
    try {
      const records = await base(TABLE_NAME)
        .select({
          filterByFormula: `OR({Email}='${email}',{userID}='${userID}')`,
          maxRecords: 1
        })
        .firstPage();

      if (records.length) {
        await base(TABLE_NAME).update(records[0].id, {
          userID, firstName, lastName, Email: email
        });
      } else {
        await base(TABLE_NAME).create({
          userID, firstName, lastName, Email: email
        });
      }
    } catch (err) {
      console.error('Airtable upsert error:', err);
    }

    // --- JWT generation with picture ---
    const payload = { id: userID, name: profile.displayName, email, picture };
    const token   = jwt.sign(payload, process.env.SESSION_SECRET, { expiresIn: '1d' });

    // --- Send inline HTML to popup ---
    res.send(`<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8"><title>Connexion réussie</title></head><body>
  <script>
    window.opener.postMessage(
      { token: '${token}', user: ${JSON.stringify(payload)} },
      '${process.env.BASE_URL}'
    );
    window.close();
  </script>
</body></html>`);
  }
);

// 3) Google One‑Tap endpoint (include picture)
app.post('/auth/onetap', async (req, res) => {
  try {
    const { credential } = req.body;
    const client = new OAuth2Client(process.env.ONE_TAP_CLIENT_ID);
    const ticket = await client.verifyIdToken({
      idToken: credential,
      audience: process.env.ONE_TAP_CLIENT_ID
    });
    const gp = ticket.getPayload();
    const user = {
      id:      gp.sub,
      name:    gp.name,
      email:   gp.email,
      picture: gp.picture
    };
    const token = jwt.sign(user, process.env.SESSION_SECRET, { expiresIn: '1d' });
    res.json({ success: true, token, user });
  } catch (err) {
    console.error('OneTap error:', err);
    res.status(401).json({ success: false, message: 'One Tap authentication failed.' });
  }
});

// 4) Protected user info route
app.get('/user', (req, res) => {
  const authHeader = req.headers.authorization||'';
  const token = authHeader.startsWith('Bearer ')? authHeader.slice(7): null;
  if (!token) return res.status(401).json({ error: 'Non connecté' });
  try {
    const payload = jwt.verify(token, process.env.SESSION_SECRET);
    res.json({ name: payload.name, email: payload.email, picture: payload.picture });
  } catch {
    res.status(401).json({ error: 'Token invalide ou expiré' });
  }
});

// 5) Upsert-user via API (for profile form)
app.post('/api/upsert-user', async (req, res) => {
  const { email, firstName, lastName, birthday, phone, userID } = req.body;
  if (!email || !userID) {
    return res.status(400).json({ error: 'email et userID nécessaires' });
  }
  try {
    const records = await base(TABLE_NAME)
      .select({ filterByFormula: `OR({Email}='${email}',{userID}='${userID}')`, maxRecords:1 })
      .firstPage();
    if (records.length) {
      await base(TABLE_NAME).update(records[0].id, { email, firstName, lastName, birthday, phone, userID });
      return res.json({ mode: 'update', id: records[0].id });
    } else {
      const record = await base(TABLE_NAME).create({ email, firstName, lastName, birthday, phone, userID });
      return res.json({ mode: 'create', id: record.id });
    }
  } catch (err) {
    console.error('Airtable API error:', err);
    return res.status(500).json({ error: 'Erreur Airtable' });
  }
});

// 6) Fallback SPA
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname,'public','index.html'));
});

// Start server
const PORT = process.env.PORT||3000;
app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
