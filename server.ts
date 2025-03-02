import express, { Request, Response, NextFunction } from 'express';
import passport from 'passport';
import fs from 'fs';
import { AuthProvider, SamlAuthOptions } from './saml/saml.interface';
import { AuthSamlStrategy } from './saml/saml.strategy';
// import { AuthSamlStrategy } from 'general-utils-client';
import { Strategy } from '@node-saml/passport-saml';
// import { SAML } from '@node-saml/node-saml';
import session from 'express-session';

// IdP acgnostic
const MY_PRIVATE_KEY = fs.readFileSync('./private-key.pem', 'utf-8');

// Example using https://mocksaml.com/
// const IDP_CERT_EXAMPLE = fs.readFileSync('apps/general-api/src/services/sso/idp_cert.pem', 'utf-8');
// const ENTRY_EXAMPLE = 'https://mocksaml.com/api/saml/sso';

// Example using Microsoft Entra ID
const MY_2_ISSUER_ID = 'http://localhost';
const MY_2_ENTRY_POINT = 'https://login.microsoftonline.com/b2d1e7ea-1e49-484c-9d88-2ce66d74b426/saml2';
const MY_2_IDP_CERT = fs.readFileSync('./test-saml-apps.pem', 'utf-8');

const DEFAULT_OPTIONS = {
  issuer: MY_2_ISSUER_ID,
  callbackUrl: 'http://localhost:3005/auth-saml/callback',
  entryPoint: MY_2_ENTRY_POINT,
  wantAssertionsSigned: true,
  idpCert: MY_2_IDP_CERT,
  privateKey: MY_PRIVATE_KEY,
  decryptionPvk: MY_PRIVATE_KEY,
  signatureAlgorithm: 'sha256',
  digestAlgorithm: 'sha256',
  wantAuthnResponseSigned: true,
  passReqToCallback: true,
} as SamlAuthOptions;

const app = express();

// passport enforce to use session
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: true,
}));

// passport initialize
app.use(passport.initialize());
app.use(passport.session());

// passport strategy
passport.use(new AuthSamlStrategy({
  teamName: 'kfi',
  strategyName: 'saml',
  authProvider: AuthProvider.MS_ENTRA_ID,
  samlOptions: DEFAULT_OPTIONS,
}) as any);


// passport serialize and deserialize
passport.serializeUser((user, done) => {
  done(null, user);
});
passport.deserializeUser((user, done) => {
  done(null, user as any);
})
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

import jwt from 'jsonwebtoken';

app.get('/',
  (req: Request, res: Response) => {
    if (req.user) {
      const token = jwt.sign(
        { user: req.user },
        'your-secret-key', // Use a secure secret key
        { expiresIn: '8h' }
      );
      res.cookie('accessToken', token, { httpOnly: true, secure: true, maxAge: 8 * 60 * 60 * 1000 });

      const html = `
      <html>
      <head>
        <title>Welcome to Client Apps</title>
      </head>
      <body>
        <h1>Welcome to Client Apps</h1>
        <ul>
          <li><a href="http://localhost/client-apps/apps-a?accessToken=${token}">App Space FE</a></li>
        </ul>
      </body>
      </html>
      `;

      res.send(html);
    }
  }
);

app.get('/auth-saml/login', passport.authenticate('saml'));

app.post('/auth-saml/callback',
  passport.authenticate('saml', {
  failureRedirect: '/error',
}), 
(req: Request, res: Response) => {
  res.redirect('/');
});

app.get('/error', (req: Request, res: Response) => {
  res.send('Error occurred when authenticating with SAML');
});

app.listen(3005, () => {
  console.log('Server listening on port 3005');
});
