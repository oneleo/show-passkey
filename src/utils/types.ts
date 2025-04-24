export type B64UrlString = string;
export type BigNumberish = string | number | bigint;
export type BytesLike = HexString | Uint8Array;
export type HexString = string;

/* Input */

export type WebAuthnCreation = {
  user?: string;
  challenge?: B64UrlString;
};

export type WebAuthnRequest = {
  credentialId?: B64UrlString;
  challenge: B64UrlString;
};

export type WebAuthnParams = {
  // Resolve error: A required parameter cannot follow an optional parameter.
  webAuthnCreation?: WebAuthnCreation;
  webAuthnRequest: WebAuthnRequest;
};

/* Output */

export type PublicKey = {
  x: bigint;
  y: bigint;
};

export type WebAuthnBase = {
  timestamp: number;
  credentialId: B64UrlString;
  aaguid: string;
  browser: string;
  os: string;
};

export type WebAuthnItem = WebAuthnBase & {
  lastUsed: number;
};

export type WebAuthnRegistration = WebAuthnBase & {
  origin: string;
  publicKey: PublicKey;
};

export type Signature = {
  r: BigNumberish;
  s: BigNumberish;
};

export type WebAuthnAuthentication = {
  timestamp: number;
  authenticatorData: HexString;
  clientDataJson: string;
  signature: Signature;
};
