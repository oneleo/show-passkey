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
  convertCertBufferToPEM,
  convertCOSEtoPKCS,
  decodeAttestationObject,
  decodeClientDataJSON,
  generateChallenge,
  generateUserID,
  getCertificateInfo,
  isCertRevoked,
  isoBase64URL,
  isoUint8Array,
  parseAuthenticatorData,
  validateCertificatePath,
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

  console.log(
    `[WebAuthn][debug][create][params]\nchallengeBase64Url: ${challengeBase64Url}\nuserId: ${userId}`,
  );

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

  console.log(
    `[WebAuthn][debug][create][raw]\nregResJSON: ${JSON.stringify(regResJSON, null, 2)}`,
  );

  const credIdBase64Url = regResJSON.id;

  const clientDataJsonBase64Url = regResJSON.response.clientDataJSON;
  const decodedClientData = decodeClientDataJSON(clientDataJsonBase64Url);
  const origin = decodedClientData.origin;

  const attestObjBase64Url = regResJSON.response.attestationObject;
  const attestObjUint8Arr = isoBase64URL.toBuffer(attestObjBase64Url);
  const decodedAttObj = decodeAttestationObject(attestObjUint8Arr);

  const fmt = decodedAttObj.get("fmt");
  const sig = decodedAttObj.get("attStmt").get("sig");
  const x5c = decodedAttObj.get("attStmt").get("x5c");
  const response = decodedAttObj.get("attStmt").get("response");
  const alg = decodedAttObj.get("attStmt").get("alg");
  const ver = decodedAttObj.get("attStmt").get("ver");
  const certInfo = decodedAttObj.get("attStmt").get("certInfo");
  const pubArea = decodedAttObj.get("attStmt").get("pubArea");

  const authDataUint8Arr = decodedAttObj.get("authData");
  const authData = parseAuthenticatorData(authDataUint8Arr);
  // console.log(`[WebAuthn][debug][create]\nauthData: ${authData}`)

  const resAuthDataUint8Arr = isoBase64URL.toBuffer(
    regResJSON.response.authenticatorData!,
  );
  console.log(
    `[WebAuthn][debug][create] RegistrationResponseJSON.response.attestationObject.authData == RegistrationResponseJSON.response.authenticatorData ?\n${isoUint8Array.toHex(authDataUint8Arr) === isoUint8Array.toHex(resAuthDataUint8Arr)}`,
  );

  const rpIdHash = isoUint8Array.toHex(authData.rpIdHash);
  const flagsBuf = Number(`0x${isoUint8Array.toHex(authData.flagsBuf)}`);
  const flags = authData.flags;
  const counter = authData.counter;
  const counterBuf = Number(`0x${isoUint8Array.toHex(authData.counterBuf)}`);
  const aaguid = authData.aaguid
    ? convertAAGUIDToString(authData.aaguid)
    : `00000000-0000-0000-0000-000000000000`;
  const credentialId = isoBase64URL.fromBuffer(authData.credentialID!);
  const credPubKeyUint8Arr = authData.credentialPublicKey!;
  const credPubKeyB64 = isoBase64URL.fromBuffer(credPubKeyUint8Arr);

  const [credPubKeyX, credPubKeyY] = parseCOSEtoXY(credPubKeyUint8Arr);
  const [resPubKeyX, resPubKeyY] = parseDERtoXY(regResJSON.response.publicKey!);
  console.log(
    `[WebAuthn][debug][create] RegistrationResponseJSON.response.attestationObject.authData.credentialPublicKey == RegistrationResponseJSON.response.publicKey ?\nx: ${credPubKeyX === resPubKeyX}; y: ${credPubKeyY === resPubKeyY}`,
  );

  if (x5c) {
    const x5cCertsInfo = x5c.map((cert) => getCertificateInfo(cert));
    // console.log(`x5cCertsInfo: ${JSON.stringify(x5cCertsInfo)}`);
    console.log(`x5c: ${isoBase64URL.fromBuffer(x5c[0])}`);

    const x5cCertsPEM = x5c.map((cert) => convertCertBufferToPEM(cert));
    // console.log(`x5cCertsPEM: ${JSON.stringify(x5cCertsPEM)}`);

    const isCertsValid = await validateCertificatePath(x5cCertsPEM);
    console.log(
      `[WebAuthn][debug][create] x5c isCertsValid: ${JSON.stringify(isCertsValid)}`,
    );

    const isCertsRevoked: boolean[] = await Promise.all(
      x5cCertsInfo.map((cert) => isCertRevoked(cert.parsedCertificate)),
    );
    console.log(
      `[WebAuthn][debug][create] x5c isCertsRevoked: ${isCertsRevoked}`,
    );
  }

  console.log(
    `[WebAuthn][debug][create]\ncredIdRaw: ${regResJSON.rawId}\ncredIdBase64Url: ${credIdBase64Url}\ndecodedClientData: ${JSON.stringify(decodedClientData, null, 2)}\natt fmt: ${fmt}\nattStmt sig: ${isoBase64URL.fromBuffer(sig!)}\nattStmt response: ${response}\nattStmt alg: ${alg}\nattStmt ver: ${ver}\nattStmt certInfo: ${certInfo}\nattStmt pubArea: ${pubArea}\nrpIdHash: ${rpIdHash}\nflagsBuf: ${flagsBuf}\nflags: ${JSON.stringify(flags)}\ncounter: ${counter}\ncounterBuf: ${counterBuf}\ncredentialId: ${credentialId}\naaguid: ${aaguid}\nuserDisplayName: ${userDisplayName}\nchallengeBase64Url: ${challengeBase64Url}\ncredPubKeyB64: ${credPubKeyB64}\ncredPubKeyXHex: 0x${credPubKeyX
      .toString(16)
      .padStart(64, "0")}\ncredPubKeyYHex: 0x${credPubKeyY
      .toString(16)
      .padStart(64, "0")}`,
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
    aaguid,
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

  console.log(
    `[WebAuthn][debug][get][raw]\nauthResJson: ${JSON.stringify(authResJson, null, 2)}`,
  );
  const clientDataJson = isoBase64URL.toUTF8String(
    authResJson.response.clientDataJSON,
  );

  const userHandleB64 = authResJson.response.userHandle;

  const authDataUrlB64 = authResJson.response.authenticatorData;
  const authData = parseAuthenticatorData(
    isoBase64URL.toBuffer(authDataUrlB64),
  );
  // console.log(`[WebAuthn][debug][get]\nauthData: ${JSON.stringify(authData, null, 2)}`);

  const rpIdHash = isoUint8Array.toHex(authData.rpIdHash);
  const flagsBuf = Number(`0x${isoUint8Array.toHex(authData.flagsBuf)}`);
  const flags = authData.flags;
  const counter = authData.counter;
  const counterBuf = Number(`0x${isoUint8Array.toHex(authData.counterBuf)}`);

  const authDataHex = `0x${isoUint8Array.toHex(
    isoBase64URL.toBuffer(authDataUrlB64),
  )}`;

  const clientDataJsonUrlB64 = authResJson.response.clientDataJSON;
  const clientDataJsonUtf8 = isoBase64URL.toUTF8String(clientDataJsonUrlB64);
  const sigUrlB64 = authResJson.response.signature;
  const [sigRUint, sigSUint] = parseSignature(sigUrlB64);

  console.log(
    `[WebAuthn][debug][get]\nclientDataJson: ${clientDataJson}\nauthData rpIdHash: ${rpIdHash}\nauthData flagsBuf: ${flagsBuf}\nauthData flags: ${JSON.stringify(flags)}\nauthData counter: ${counter}\nauthData counterBuf: ${counterBuf}\nuserHandleB64: ${userHandleB64}\nauthDataHex: ${authDataHex}\nclientDataJsonUtf8: ${clientDataJsonUtf8}\nsigUrlB64: ${sigUrlB64}\nsignatureR: ${sigRUint}\nsignatureS: 0x${sigSUint}`,
  );

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

const parseCOSEtoXY = (
  credentialPublicKeyUint8Arr: Uint8Array<ArrayBufferLike>,
): [bigint, bigint] => {
  const credPubKeyObjUint8Arr = convertCOSEtoPKCS(credentialPublicKeyUint8Arr); // return isoUint8Array.concat([tag, x, y]);
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

const parseDERtoXY = (responsePublicKeyB64: string): [bigint, bigint] => {
  const resPubKeyUint8Arr = isoBase64URL.toBuffer(responsePublicKeyB64);

  // DER 公鑰格式是 SubjectPublicKeyInfo，尾端會有 uncompressed key: 0x04 + X + Y
  const uncompressedStart = resPubKeyUint8Arr.findIndex((b) => b === 0x04);

  if (
    uncompressedStart === -1 ||
    resPubKeyUint8Arr.length < uncompressedStart + 65
  ) {
    throw new Error("Invalid public key format");
  }

  const keyBytes = resPubKeyUint8Arr.subarray(
    uncompressedStart + 1,
    uncompressedStart + 65,
  );
  const xHex = `0x${isoUint8Array.toHex(keyBytes.subarray(0, 32))}`;
  const xUint256 = BigInt(xHex);
  const yHex = `0x${isoUint8Array.toHex(keyBytes.subarray(32, 64))}`;
  const yUint256 = BigInt(yHex);

  return [xUint256, yUint256];
};
