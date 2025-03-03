## Summary

This is sample demo apps utilziing SAML for authentication. This utilize sample SAML https://mocksaml.com/

## Run server.ts by VSCode Debugger

1. Open VSCode.
2. On run debug configuration, select `Debug Apps 3005` (this is for SAML issuer).
3. On debug console you should see `Server listening on port 3005`.
4. On run debug configuration, select `Debug Apps 3006` (this is for SAML consumer).
5. On debug console you should see `Server listening on port 3006`.
4. Open browser and go to `http://localhost:3005/login`
