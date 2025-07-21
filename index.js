// index.js
require('dotenv').config();
const express  = require('express');
const passport = require('passport');
const jwt      = require('jsonwebtoken');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const Airtable      = require('airtable');

const app   = express();
const PORT  = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL;               // ex. "https://votre-app.onrender.com"
const JWT_SECRET = process.env.JWT_SECRET;           // pour signer le token
const TABLE = process.env.AIRTABLE_TABLE || 'Users'; // nom de la table

// Initialise Airtable
const base = new Airtable({ apiKey: process.env.AIRTABLE_API_KEY })
  .base(process.env.AIRTABLE_BASE_ID);

// Passport Google OAuth
passport.use(new GoogleStrategy({
    clientID:     process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL:  `${BASE_URL}/auth/google/callback`
  },
  (accessToken, refreshToken, profile, cb) => {
    // on transmet le profil à req.user
    return cb(null, profile);
  }
));
app.use(passport.initialize());

// Route de démarrage OAuth
app.get('/auth/google',
  passport.authenticate('google', {
    session: false,
    scope:   ['profile', 'email']
  })
);

// Fonction utilitaire pour trouver un record par Email
async function findRecordByEmail(email) {
  const filter = `{Email}="${email.replace(/"/g,'\\"')}"`;
  const records = await base(TABLE)
    .select({ filterByFormula: filter, maxRecords: 1 })
    .firstPage();
  return records[0] || null;
}

// Callback OAuth : upsert en ne complétant que les champs vides
app.get('/auth/google/callback',
  passport.authenticate('google', { session: false, failureRedirect: BASE_URL }),
  async (req, res) => {
    const p     = req.user;
    const email = (p.emails && p.emails[0].value) || '';
    try {
      console.log('↪️ Upsert Airtable pour', email);
      const record = await findRecordByEmail(email);

      if (record) {
        // On ne met à jour que les champs manquants
        const updates = {};
        const fields  = record.fields;

        if (!fields.firstName && p.name?.givenName)   updates.firstName = p.name.givenName;
        if (!fields.lastName  && p.name?.familyName) updates.lastName  = p.name.familyName;
        if (!fields.name      && p.displayName)      updates.name      = p.displayName;
        // … ajoutez ici d’autres champs Google si besoin …

        if (Object.keys(updates).length > 0) {
          await base(TABLE).update(record.id, updates);
          console.log('✅ Champs complétés :', updates);
        } else {
          console.log('ℹ️ Aucun champ à compléter, enregistrement intact');
        }
      } else {
        // Création normale
        await base(TABLE).create({
          Email:     email,
          name:      p.displayName,
          firstName: p.name?.givenName  || '',
          lastName:  p.name?.familyName || ''
          // … ajoutez d’autres champs par défaut si souhaité …
        });
        console.log('✅ Nouvel utilisateur créé pour', email);
      }
    } catch (err) {
      console.error('❌ Erreur Airtable upsert :', err);
    }

    // Génération du JWT et envoi à la popup front
    const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '2h' });
    res.send(`
      <script>
        window.opener.postMessage({ token: "${token}" }, "${BASE_URL}");
        window.close();
      </script>
    `);
  }
);

// Démarrage du serveur
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
