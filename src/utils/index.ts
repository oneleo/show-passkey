// --- Modules ---
import * as aaguids from "./aaguids";
import * as bytes from "./bytes";
import * as json from "./json";
import * as webAuthn from "./webAuthn";

// --- Export Modules ---
export { aaguids, bytes, json, webAuthn };

// --- Export Functions ---
export const { isHex, fromAny, concat, toString } = bytes;
export const { stringify } = json;
export const { createWebAuthn, requestWebAuthn } = webAuthn;
export const { authenticators } = aaguids;

// --- Export Types ---
export type {
  B64UrlString,
  BigNumberish,
  BytesLike,
  HexString,
  PublicKey,
  Signature,
  WebAuthnAuthentication,
  WebAuthnCreation,
  WebAuthnItem,
  WebAuthnParams,
  WebAuthnRegistration,
  WebAuthnRequest,
} from "./types";
