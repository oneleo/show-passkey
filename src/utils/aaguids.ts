// Refer: https://github.com/passkeydeveloper/passkey-authenticator-aaguids/blob/main/combined_aaguid.json
import combinedAaguid from "./combined_aaguid.json";

export type AuthenticatorData = {
  name: string;
  icon_light?: string | null;
  icon_dark?: string | null;
};

export type AuthenticatorMap = {
  [key: string]: AuthenticatorData;
};

export const authenticators: AuthenticatorMap = combinedAaguid;

// Other tools:
// https://passkeydeveloper.github.io/passkey-authenticator-aaguids/explorer/?combined
// https://webauthn.passwordless.id/demos/authenticators
//
// https://github.com/passkeydeveloper/passkey-authenticator-aaguids
// https://github.com/passwordless-id/webauthn/blob/main/src/authenticatorMetadata.ts
