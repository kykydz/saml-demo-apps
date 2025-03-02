import { Strategy, Profile, VerifiedCallback } from '@node-saml/passport-saml';
import { AuthProvider, ISamlConfig, JsonIdentityClaims, MSEntraIDAttributes, SamlVerifyWithRequest } from './saml.interface';
import { Request } from 'express';

export class AuthSamlStrategy extends Strategy {
  private authProvider: AuthProvider;
  /**
   * Initializes the SAML strategy with the given configuration.
   *
   * @param {ISamlConfig} config - The configuration for the strategy.
   * @param {SamlConfig} [config.samlOptions] - The configuration for the passport-saml package.
   * @param {VerifyWithoutRequest} [config.signOnVerifyHandler] - A callback to verify the user profile.
   * @param {VerifyWithoutRequest} [config.logoutVerifyHandler] - A placeholder callback to verify the user profile on logout (not implemented yet).
   *
   * @example
   * const samlConfig: ISamlConfig = {
   *   teamName: 'kfi',
   *   authProvider: AuthProvider.MS_ENTRA_ID,
   *   strategyName: 'saml',
   *   samlConfig: {
   *     issuer: 'http://kfi-host',
   *     callbackUrl: 'http://kfi-host:3005/auth-saml/callback',
   *     entryPoint: 'https://login.example.com/saml2',
   *   },
   *   signOnVerifyHandler: async (profile, done) => {
   *     done(null, profile);
   *   },
   * };
   */
  constructor(config: ISamlConfig) {
    const samlOptions = config.samlOptions;
    const defaultSignOnVerifyFunc: SamlVerifyWithRequest = async (req: any, profile: Profile | null, done: VerifiedCallback) => {
      try {
        const validatedProfile = this.validate(profile as Profile);
        done(null, validatedProfile);
      } catch (error: unknown) {
        done(error as Error, {
          profileClaimed: profile,
        }, {
          lastError: error,
          message: 'Error in user claimed validation',
        });
      }
    };
    const signOnVerifyFunc = config.signOnVerifyHandler ?? defaultSignOnVerifyFunc;

    // This is only dummy for implementation
    const defaultLogoutVerifyFunc: SamlVerifyWithRequest = async (req: any, profile: Profile | null, done: VerifiedCallback) => {
      done(null, {
        profileClaimed: profile,
      });
    };
    const logoutVerifyFunc = config.logoutVerifyHandler ?? defaultLogoutVerifyFunc;

    super(samlOptions, defaultSignOnVerifyFunc, logoutVerifyFunc);
    this.name = config.strategyName;
    this.authProvider = config.authProvider;
  }

  validate(profile?: Profile): JsonIdentityClaims {
    try {
      if (!profile) {
        throw new Error('invalid user attributes');
      }

      let jsonClaims: JsonIdentityClaims;
      let assertions: Record<string, any> | undefined;
      
      let tokenCreatedAt: Date;
      let tokenExpiredAt: Date;
      let expiryDuration: Record<string, any>;
      switch (this.authProvider) {
        case AuthProvider.MS_ENTRA_ID:
          assertions = profile.getAssertion?.();
          // get assertion condition https://learn.microsoft.com/en-us/entra/identity-platform/reference-saml-tokens#claims-in-saml-tokens
          // justification from: https://app.clickup.com/t/86cy474mt
          tokenCreatedAt = new Date(assertions?.Assertion.Conditions[0].$.NotBefore);
          tokenExpiredAt = new Date(assertions?.Assertion.Conditions[0].$.NotOnOrAfter);
          const durationMilliseconds = tokenExpiredAt.getTime() - tokenCreatedAt.getTime();
          const hours = Math.floor(durationMilliseconds / (1000 * 60 * 60));
          const minutes = Math.floor((durationMilliseconds % (1000 * 60 * 60)) / (1000 * 60));
          const seconds = Math.floor((durationMilliseconds % (1000 * 60)) / 1000);
          expiryDuration = { hours, minutes, seconds };

          jsonClaims = {
            tenantId: profile['http://schemas.microsoft.com/identity/claims/tenantid'],
            objectId: profile['http://schemas.microsoft.com/identity/claims/objectidentifier'],
            displayName: profile['http://schemas.microsoft.com/identity/claims/displayname'],
            identityProvider: profile['http://schemas.microsoft.com/identity/claims/identityprovider'],
            authenticationMethods: profile['http://schemas.microsoft.com/claims/authnmethodsreferences'],
            givenName: profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname'],
            surname: profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname'],
            emailAddress: profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'],
            name: profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name'],
            // Token Lifetime
            expiry: {
              createdAt: tokenCreatedAt,
              expiredAt: tokenExpiredAt,
              duration: expiryDuration,
            },
          } as MSEntraIDAttributes;
          break;
        default:
          throw new Error(`Unable to parse profile claim for auth provider: ${this.authProvider}`);
      }

      return jsonClaims;
    } catch (e) {
      throw new Error('invalid user attributes');
    }
  }

  getStrategy() {
    return this.getStrategy;
  }
}