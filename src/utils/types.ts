import type { JwtHeader } from "jwt-decode";
export type B64UrlString = string;
export type BigNumberish = string | number | bigint;
export type BytesLike = HexString | Uint8Array;
export type HexString = string;

// --- WebAuthn  Input ---

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

// --- WebAuthn output ---

export type PublicKey = {
  x: bigint;
  y: bigint;
};

export type WebAuthnBase = {
  createdAt: number;
  user: string;
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
  lastUsed: number;
  authenticatorData: HexString;
  clientDataJson: string;
  signature: Signature;
};

// --- FIDO Metadata Service Type ---

// Refer: https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html

export type AAID = string;
export type AAGUID = string;

export interface MetadataBLOBPayloadEntry {
  aaid?: AAID;
  aaguid?: AAGUID;
  attestationCertificateKeyIdentifiers?: string[];
  metadataStatement: MetadataStatement;
  biometricStatusReports?: BiometricStatusReport[];
  statusReports: StatusReport[];
  timeOfLastStatusChange: string;
  rogueListURL?: string;
  rogueListHash?: string;
}

export interface MetadataStatement {
  legalHeader: string;
  aaid?: AAID;
  aaguid?: AAGUID;
  attestationCertificateKeyIdentifiers?: string[];
  description: string;
  alternativeDescriptions?: { [key: string]: string };
  authenticatorVersion: number;
  protocolFamily: string;
  schema: number;
  upv: { major: number; minor: number }[];
  authenticationAlgorithms: string[];
  publicKeyAlgAndEncodings: string[];
  attestationTypes: string[];
  userVerificationDetails: VerificationMethodANDCombinations[];
  keyProtection: string[];
  isKeyRestricted: boolean;
  isFreshUserVerificationRequired: boolean;
  matcherProtection: string[];
  cryptoStrength: number;
  attachmentHint: string[];
  tcDisplay: string[];
  tcDisplayContentType?: string;
  tcDisplayPNGCharacteristics?: DisplayPNGCharacteristicsDescriptor[];
  attestationRootCertificates: string[];
  ecdaaTrustAnchors?: EcdaaTrustAnchor[];
  icon: string;
  supportedExtensions?: ExtensionDescriptor[];
  authenticatorGetInfo?: AuthenticatorGetInfo;
}

export interface BiometricStatusReport {
  certLevel: number;
  modality: string;
  effectiveDate?: string;
  certificationDescriptor?: string;
  certificateNumber?: string;
  certificationPolicyVersion?: string;
  certificationRequirementsVersion?: string;
}

export interface StatusReport {
  status: AuthenticatorStatus;
  effectiveDate?: string;
  authenticatorVersion?: number;
  certificate?: string;
  url?: string;
  certificationDescriptor?: string;
  certificateNumber?: string;
  certificationPolicyVersion?: string;
  certificationRequirementsVersion?: string;
}

enum AuthenticatorStatus {
  NOT_FIDO_CERTIFIED = "NOT_FIDO_CERTIFIED",
  FIDO_CERTIFIED = "FIDO_CERTIFIED",
  USER_VERIFICATION_BYPASS = "USER_VERIFICATION_BYPASS",
  ATTESTATION_KEY_COMPROMISE = "ATTESTATION_KEY_COMPROMISE",
  USER_KEY_REMOTE_COMPROMISE = "USER_KEY_REMOTE_COMPROMISE",
  USER_KEY_PHYSICAL_COMPROMISE = "USER_KEY_PHYSICAL_COMPROMISE",
  UPDATE_AVAILABLE = "UPDATE_AVAILABLE",
  REVOKED = "REVOKED",
  SELF_ASSERTION_SUBMITTED = "SELF_ASSERTION_SUBMITTED",
  FIDO_CERTIFIED_L1 = "FIDO_CERTIFIED_L1",
  FIDO_CERTIFIED_L1plus = "FIDO_CERTIFIED_L1plus",
  FIDO_CERTIFIED_L2 = "FIDO_CERTIFIED_L2",
  FIDO_CERTIFIED_L2plus = "FIDO_CERTIFIED_L2plus",
  FIDO_CERTIFIED_L3 = "FIDO_CERTIFIED_L3",
  FIDO_CERTIFIED_L3plus = "FIDO_CERTIFIED_L3plus",
}

export interface RogueListEntry {
  sk: string;
  date: string;
}

export interface MetadataBLOBPayload {
  legalHeader: string;
  no: number;
  nextUpdate: string;
  entries: MetadataBLOBPayloadEntry[];
}

export interface MetadataBLOB {
  header: string;
  payload: string;
  signature: string;
}

// FIDO Metadata Statement Type
// Refer: https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html

export interface CodeAccuracyDescriptor {
  base: number;
  minLength: number;
  maxRetries?: number;
  blockSlowdown?: number;
}

export interface BiometricAccuracyDescriptor {
  selfAttestedFRR?: number;
  selfAttestedFAR?: number;
  maxTemplates?: number;
  maxRetries?: number;
  blockSlowdown?: number;
}

export interface PatternAccuracyDescriptor {
  minComplexity: number;
  maxRetries?: number;
  blockSlowdown?: number;
}

export interface VerificationMethodDescriptor {
  userVerificationMethod: string;
  caDesc?: CodeAccuracyDescriptor;
  baDesc?: BiometricAccuracyDescriptor;
  paDesc?: PatternAccuracyDescriptor;
}

export type VerificationMethodANDCombinations = VerificationMethodDescriptor[];

export interface rgbPaletteEntry {
  r: number;
  g: number;
  b: number;
}

export interface DisplayPNGCharacteristicsDescriptor {
  width: number;
  height: number;
  bitDepth: number;
  colorType: number;
  compression: number;
  filter: number;
  interlace: number;
  plte?: rgbPaletteEntry[];
}

export interface EcdaaTrustAnchor {
  X: string;
  Y: string;
  c: string;
  sx: string;
  sy: string;
  G1Curve: string;
}

export interface ExtensionDescriptor {
  id: string;
  tag?: number;
  data?: string;
  fail_if_unknown: boolean;
}

export interface AuthenticatorGetInfo {
  versions: string[];
  extensions?: string[];
  aaguid?: string;
  options?: {
    plat?: boolean;
    rk?: boolean;
    clientPin?: boolean;
    up?: boolean;
    uv?: boolean;
    uvToken?: boolean;
    config?: boolean;
  };
  maxMsgSize?: number;
  pinUvAuthProtocols?: number[];
  maxCredentialCountInList?: number;
  maxCredentialIdLength?: number;
  transports?: string[];
  algorithms?: { type: string; alg: number }[];
  maxAuthenticatorConfigLength?: number;
  defaultCredProtect?: number;
  firmwareVersion?: number;
}

// JWT type

export interface Jwt {
  header: JwtHeader;
  payload: MetadataBLOBPayload;
  signature: string;
}
