import express, { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

const SECRET_KEY = 'a-secret-key';
const REFRESH_SECRET_KEY = 'a-refresh-secret-key';

app.get('/client-apps-x/login', (req: Request, res: Response) => {
  const { accessToken } = req.query;
  if (!accessToken) {
    res.status(401).send('Access denied');
  }
  
  try {
    // Validate accessToken
    const decoded = jwt.verify(accessToken as string, SECRET_KEY);

    // Generate refresh token
    const refreshToken = jwt.sign({ user: req.body.user }, REFRESH_SECRET_KEY, { expiresIn: '1d' });

    // Inject req.authorization with refresh token
    req.headers['authorization'] = refreshToken;
    res.cookie('refreshToken', refreshToken, { httpOnly: true, secure: true, maxAge: 86400000 }); // 1 day

    // Redirect to protected app
    res.redirect('/client-apps-x/protected');
  } catch (error) {
    res.status(401).send('Invalid access token');
  }
});

const validateRefreshToken = (req: Request, res: Response, next: NextFunction) => {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    res.status(403).send('Access denied');
  }

  try {
    const decoded = jwt.verify(refreshToken as string, REFRESH_SECRET_KEY);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).send('Invalid refresh token');
  }
};

app.get('/client-apps-x/protected', validateRefreshToken, (req: Request, res: Response) => {
  res.send('You have accessed a protected route');
});

app.listen(3006, () => {
  console.log('Server listening on port 3006');
});

