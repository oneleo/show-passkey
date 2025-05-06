// Refer:
// https://github.com/passkeydeveloper/passkey-authenticator-aaguids/blob/main/combined_aaguid.json
import type { MetadataBLOBPayloadEntry, MetadataBLOBPayload } from "./types";

let aaguidsCache: MetadataBLOBPayload | null = null;

export const getAuthenticatorData = async (
  aaguid: string,
): Promise<MetadataBLOBPayloadEntry | undefined> => {
  if (!aaguidsCache) {
    const { default: loaded } = (await import("./aaguids.json")) as {
      default: MetadataBLOBPayload;
    };
    aaguidsCache = loaded;
  }
  return aaguidsCache.entries.find((entry) => entry.aaguid === aaguid);
};

// --- AAGUID tools ---
// Explorer:
// https://passkeydeveloper.github.io/passkey-authenticator-aaguids/explorer/?combined
// https://webauthn.passwordless.id/demos/authenticators
// Source code:
// https://github.com/passkeydeveloper/passkey-authenticator-aaguids
// https://github.com/passwordless-id/webauthn/blob/main/src/authenticatorMetadata.ts
