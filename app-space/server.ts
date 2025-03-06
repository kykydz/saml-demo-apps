import express, { Request, Response, NextFunction } from 'express';
import passport from 'passport';
import fs from 'fs';
import { AuthProvider, SamlAuthOptions } from '../saml/saml.interface';
import { AuthSamlStrategy } from '../saml/saml.strategy';
import session from 'express-session';

// IdP acgnostic
// const MY_PRIVATE_KEY = fs.readFileSync('./dummy-priv-key', 'utf-8');
// const MY_2_ISSUER_ID = 'http://localhost';

// Example using https://mocksaml.com/
// const IDP_CERT = fs.readFileSync('idp-cert-mock-sample', 'utf-8');
// const ENTRY_POINT = 'https://mocksaml.com/api/saml/sso';

// Personal Microsoft Entra ID
// const LOCAL_HOST = 'http://localhost:3000';
// const ISSUER_ID = 'http://localhost';
// const MY_PRIVATE_KEY = fs.readFileSync('./komunal_private_key.pem', 'utf-8');
// const ENTRY_POINT = 'https://login.microsoftonline.com/b2d1e7ea-1e49-484c-9d88-2ce66d74b426/saml2';
// const IDP_CERT = fs.readFileSync('./test-saml-apps_3.pem', 'utf-8');

/***
 * Error:
 * 1. Error: Invalid document signature at SAML.validatePostResponseAsync => wrong IdP cert
 * 2. Error: TypeError: keyInfo is not in PEM format or in base64 format =>
 * 3. AADSTS76023: The signature of the received authentication request is invalid, please contact the administrator to resolve the issue. => wrong private key
 */

// Microsoft Komunal
const LOCAL_HOST = 'http://localhost:3000';
// const LOCAL_HOST = 'https://8cec-36-73-120-110.ngrok-free.app';
const ISSUER_ID = 'https://staging-apps.komunalgroup.com';
const MY_PRIVATE_KEY = fs.readFileSync('./komunal_private_key.pem', 'utf-8');
const ENTRY_POINT = 'https://login.microsoftonline.com/8b5d6ca5-b3b7-4000-acfc-4af0884a87b1/saml2';
const IDP_CERT = fs.readFileSync('./Staging-KomunalGroup-fromraw.pem', 'utf-8');

const DEFAULT_OPTIONS = {
  issuer: ISSUER_ID,
  callbackUrl: LOCAL_HOST + '/assertion/callback',
  entryPoint: ENTRY_POINT,
  wantAssertionsSigned: true,
  idpCert: IDP_CERT,
  privateKey: MY_PRIVATE_KEY,
  decryptionPvk: MY_PRIVATE_KEY,
  signatureAlgorithm: 'sha256',
  digestAlgorithm: 'sha256',
  wantAuthnResponseSigned: false,
  passReqToCallback: true,
} as SamlAuthOptions;

const SECRET_KEY = 'a-secret-key';

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
  teamName: 'kgs',
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
        SECRET_KEY, // Use a secure secret key
        { expiresIn: '8h' }
      );
      res.cookie('accessToken', token, { httpOnly: true, secure: true, maxAge: 8 * 60 * 60 * 1000 });

      const html = `
      <html>
      <head>
        <title>Welcome to Client Apps</title>
      </head>
      <body>
        <pre><code>${JSON.stringify(req.user, null, 2)}</code></pre>
        <h1>Welcome to Client Apps</h1>
        <ul>
          <li><a href="http://localhost:3006/client-apps-x/login?accessToken=${token}">App Space FE</a></li>
        </ul>
      </body>
      </html>
      `;

      res.send(html);
    }
  }
);

app.get('/auth-saml/login', passport.authenticate('saml'));

app.post('/assertion/callback',
  passport.authenticate('saml', {
  failureRedirect: '/error',
}), 
(req: Request, res: Response) => {
  res.redirect('/');
});

app.get('/error', (req: Request, res: Response) => {
  res.send('Error occurred when authenticating with SAML');
});

app.listen(3000, () => {
  console.log('Server listening on port 3000');
});
