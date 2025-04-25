import { p256 } from "@noble/curves/p256";
import type {
  AttestationConveyancePreference,
  COSEAlgorithmIdentifier,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialDescriptorJSON,
  PublicKeyCredentialRequestOptionsJSON,
  PublicKeyCredentialType,
  UserVerificationRequirement,
} from "@simplewebauthn/browser";
import {
  startAuthentication,
  startRegistration,
} from "@simplewebauthn/browser";
import {
  convertAAGUIDToString,
  convertCOSEtoPKCS,
  decodeAttestationObject,
  decodeClientDataJSON,
  generateChallenge,
  generateUserID,
  isoBase64URL,
  isoUint8Array,
  parseAuthenticatorData,
} from "@simplewebauthn/server/helpers";

import { DateTime } from "luxon";

import { UAParser } from "ua-parser-js";
import type {
  B64UrlString,
  WebAuthnAuthentication,
  WebAuthnCreation,
  WebAuthnRegistration,
  WebAuthnRequest,
} from "./types";

export const createWebAuthn = async (
  params?: WebAuthnCreation,
): Promise<WebAuthnRegistration> => {
  const createdAt = Date.now();
  const uaParser = new UAParser();

  const utcIsoString = DateTime.fromMillis(createdAt).toUTC().toISO();

  const challengeBase64Url =
    params?.challenge && isoBase64URL.isBase64(params.challenge)
      ? params.challenge
      : isoBase64URL.fromBuffer(await generateChallenge());

  const userDisplayName = params?.user?.trim()
    ? decodeURIComponent(params.user)
    : "user";
  const userId = isoBase64URL.fromBuffer(await generateUserID());
  const userName = `${utcIsoString}-${userId.slice(0, 6)}-${
    userDisplayName.slice(0, 9) || "user"
  }`;

  // Create WebAuthn
  const regResJSON = await startRegistration({
    useAutoRegister: false,
    optionsJSON: {
      rp: {
        name: defaultWebAuthn.rpName,
      },
      user: {
        id: userId,
        name: userName,
        displayName: userDisplayName,
      },
      challenge: challengeBase64Url,
      pubKeyCredParams: [
        {
          alg: defaultWebAuthn.pubKeyCredAlgEs256,
          type: defaultWebAuthn.pubKeyCredType,
        },
        {
          alg: defaultWebAuthn.pubKeyCredAlgRs256,
          type: defaultWebAuthn.pubKeyCredType,
        },
      ],
      timeout: defaultWebAuthn.timeout,
      authenticatorSelection: {
        requireResidentKey: defaultWebAuthn.requireResidentKey,
        residentKey: defaultWebAuthn.residentKeyRequirement,
        userVerification: defaultWebAuthn.userVerificationRequirement,
      },
      attestation: defaultWebAuthn.attestationConveyancePreference,
      extensions: defaultWebAuthn.extensions,
    } as PublicKeyCredentialCreationOptionsJSON,
  });

  const credIdBase64Url = regResJSON.id;

  const clientDataJsonBase64Url = regResJSON.response.clientDataJSON;
  const decodedClientData = decodeClientDataJSON(clientDataJsonBase64Url);
  const origin = decodedClientData.origin;

  const attestObjBase64Url = regResJSON.response.attestationObject;
  const attestObjUint8Arr = isoBase64URL.toBuffer(attestObjBase64Url);
  const decodedAttObj = decodeAttestationObject(attestObjUint8Arr);

  const authData = parseAuthenticatorData(decodedAttObj.get("authData"));
  const credPubKeyUint8Arr = authData.credentialPublicKey!;
  const [credPubKeyX, credPubKeyY] =
    parseCredentialPublicKey(credPubKeyUint8Arr);

  console.log(
    `[WebAuthn][debug]\nuserDisplayName: ${userDisplayName}\nchallengeBase64Url: ${challengeBase64Url}\ncredPubKeyXHex: 0x${credPubKeyX
      .toString(16)
      .padStart(64, "0")}\ncredPubKeyYHex: 0x${credPubKeyY
      .toString(16)
      .padStart(64, "0")}`,
  );

  console.log(
    `aaguid:\n${!!authData.aaguid}\n${authData.aaguid}\n${convertAAGUIDToString(
      authData.aaguid!,
    )}`,
  );

  return {
    createdAt,
    origin,
    user: userDisplayName,
    credentialId: credIdBase64Url,
    publicKey: {
      x: credPubKeyX,
      y: credPubKeyY,
    },
    aaguid: authData.aaguid
      ? convertAAGUIDToString(authData.aaguid)
      : `00000000-0000-0000-0000-000000000000`,
    browser: uaParser.getBrowser().name || `Unknown broswer`,
    os: uaParser.getOS().name || `Unknown OS`,
  };
};

export const requestWebAuthn = async (
  params: WebAuthnRequest,
): Promise<WebAuthnAuthentication> => {
  const lastUsed = Date.now();

  const authResJson = await startAuthentication({
    useBrowserAutofill: false,
    verifyBrowserAutofillInput: true,
    optionsJSON: {
      ...(params.credentialId
        ? {
            allowCredentials: [
              { id: params.credentialId, type: defaultWebAuthn.pubKeyCredType },
            ] as PublicKeyCredentialDescriptorJSON[],
          }
        : {}),
      userVerification: defaultWebAuthn.userVerificationRequirement,
      challenge: params.challenge,
    } as PublicKeyCredentialRequestOptionsJSON,
  });

  const authDataUrlB64 = authResJson.response.authenticatorData;
  const authDataHex = `0x${isoUint8Array.toHex(
    isoBase64URL.toBuffer(authDataUrlB64),
  )}`;

  const clientDataJsonUrlB64 = authResJson.response.clientDataJSON;
  const clientDataJsonUtf8 = isoBase64URL.toUTF8String(clientDataJsonUrlB64);
  const sigUrlB64 = authResJson.response.signature;
  const [sigRUint, sigSUint] = parseSignature(sigUrlB64);
  return {
    lastUsed,
    authenticatorData: authDataHex,
    clientDataJson: clientDataJsonUtf8,
    signature: {
      r: sigRUint,
      s: sigSUint,
    },
  };
};

export const defaultWebAuthn = {
  // Supported credential algorithms (COSE identifiers)
  // Prefer ES256, but also accept RS256, ES384, ES512, and EdDSA.
  // Refer: https://www.iana.org/assignments/cose/cose.xhtml
  pubKeyCredAlgEs256: -7 as COSEAlgorithmIdentifier, // ES256 (default and widely supported)
  pubKeyCredAlgRs256: -257 as COSEAlgorithmIdentifier, // RS256 (used by Windows Hello, etc.)
  pubKeyCredAlgEs384: -35 as COSEAlgorithmIdentifier, // ES384 (stronger ECDSA)
  pubKeyCredAlgEs512: -36 as COSEAlgorithmIdentifier, // ES512 (strongest ECDSA)
  pubKeyCredAlgEdDsa: -8 as COSEAlgorithmIdentifier, // EdDSA (e.g. Ed25519)

  // Requests full device attestation info like AAGUID
  attestationConveyancePreference: "direct" as AttestationConveyancePreference,
  // Credential type: public key
  pubKeyCredType: "public-key" as PublicKeyCredentialType,
  // Require a resident key to be stored on the authenticator (for Passkey support)
  residentKeyRequirement: "required" as ResidentKeyRequirement,
  // Enforce that resident keys must be used (essential for passwordless/passkey flow)
  requireResidentKey: true,
  // Require user verification (e.g. biometrics or PIN)
  userVerificationRequirement: "required" as UserVerificationRequirement,
  // Timeout for the registration (in milliseconds), e.g., 6 minutes
  timeout: 360000,
  // Relying Party name shown to the user
  rpName: "Show Passkey",
  // Request support for largeBlob storage if available
  extensions: {
    largeBlob: {
      support: "preferred", // or "required"
    },
  },
};

const parseCredentialPublicKey = (
  credentialPublicKey: Uint8Array<ArrayBufferLike>,
): [bigint, bigint] => {
  const credPubKeyObjUint8Arr = convertCOSEtoPKCS(credentialPublicKey); // return isoUint8Array.concat([tag, x, y]);
  const credPubKeyXLen = (credPubKeyObjUint8Arr.length - 1) / 2; // tag length = 1

  const credPubKeyXUint8Arr = credPubKeyObjUint8Arr.subarray(
    1,
    1 + credPubKeyXLen,
  );
  const credPubKeyXHex = `0x${isoUint8Array.toHex(credPubKeyXUint8Arr)}`;
  const credPubKeyXUint256 = BigInt(credPubKeyXHex);
  const credPubKeyYUint8Arr = credPubKeyObjUint8Arr.subarray(
    1 + credPubKeyXLen,
  );
  const credPubKeyYHex = `0x${isoUint8Array.toHex(credPubKeyYUint8Arr)}`;
  const credPubKeyYUint256 = BigInt(credPubKeyYHex);

  return [credPubKeyXUint256, credPubKeyYUint256];
};

const parseSignature = (signature: B64UrlString): [bigint, bigint] => {
  if (!isoBase64URL.isBase64URL(signature)) {
    console.log(`${signature} is not Base64Url`);
    return [BigInt(0), BigInt(0)];
  }
  const p256Sig = p256.Signature.fromDER(
    isoUint8Array.toHex(isoBase64URL.toBuffer(signature)),
  );
  // If your library generates malleable signatures, such as s-values in the upper range, calculate a new s-value
  const p256SigS =
    p256Sig.s > p256.CURVE.n / 2n ? p256.CURVE.n - p256Sig.s : p256Sig.s;

  return [p256Sig.r, p256SigS];
};
