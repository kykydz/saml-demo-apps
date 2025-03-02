import { PassportSamlConfig, SignatureAlgorithm, VerifyWithoutRequest, VerifyWithRequest } from '@node-saml/passport-saml';

export type SamlAuthOptions = PassportSamlConfig;
export type SamlSignatureAlgorithm = SignatureAlgorithm;
export type SamlVerifyWithRequest = VerifyWithRequest;

export enum AuthProvider {
  MS_ENTRA_ID = 'ms-entra-id',
  GOOGLE = 'google',
}

export interface ISamlConfig {
  teamName: string,
  authProvider: AuthProvider,
  strategyName: string | 'saml'
  samlOptions: SamlAuthOptions,
  signOnVerifyHandler?: SamlVerifyWithRequest,
  logoutVerifyHandler?: SamlVerifyWithRequest
}

export interface MSEntraIDAttributes {
  tenantId: string;
  objectId: string;
  displayName: string;
  identityProvider: string;
  authenticationMethods: string[];
  givenName: string;
  surname: string;
  emailAddress: string;
  name: string;
  expiry: {
    createdAt: Date,
    expiredAt: Date,
    duration: {
      hours: number,
      minutes: number,
      seconds: number
    }
  }
  [key: string]: unknown;
}

export type JsonIdentityClaims = MSEntraIDAttributes & Record<string, unknown>;