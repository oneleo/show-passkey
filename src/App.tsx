import { useEffect, useState } from "react";
import "./App.css";
import { useWebAuthnItems } from "./hooks/useWebAuthnItems";

import type {
  BytesLike,
  WebAuthnAuthentication,
  WebAuthnRegistration,
} from "./utils";
import { createWebAuthn, fromAny, requestWebAuthn, toString } from "./utils";

import { PasskeyItems } from "./components/passkeyItems";

function App() {
  const [errorMessage, setErrorMessage] = useState<string>(``);

  const { webAuthnItems, addItem, updateItem, deleteItem } = useWebAuthnItems();

  const [passkeyUserName, setPasskeyUserName] = useState<string>(``);

  const [selectedCredentialId, setSelectedCredentialId] = useState<string>();

  useEffect(() => {
    console.log(`selectedCredentialId: ${selectedCredentialId}`);
  }, [selectedCredentialId]);

  // --- Handlers ---

  // Register
  const registerWebAuthn = async () => {
    const regRes: WebAuthnRegistration = await createWebAuthn({
      user: passkeyUserName,
    });

    addItem({
      createdAt: regRes.createdAt,
      user: regRes.user,
      credentialId: regRes.credentialId,
      aaguid: regRes.aaguid,
      browser: regRes.browser,
      os: regRes.os,
      lastUsed: regRes.createdAt,
    });
  };

  // Authenticate
  const authenticateWebAuthn = async (credentialId?: string) => {
    const challenge: BytesLike = "0x123456";
    const challengeB64Url = toString(fromAny(challenge), "base64url");

    const authRes: WebAuthnAuthentication = await requestWebAuthn({
      credentialId,
      challenge: challengeB64Url,
    });

    if (!credentialId) {
      return;
    }

    updateItem({ credentialId, lastUsed: authRes.lastUsed });
  };

  const handlePasskeyUserNameChange = (input: string) => {
    setPasskeyUserName(input);
    try {
      if (input.length >= 12) {
        throw new Error(`Passkey user name is too long`);
      }
      setErrorMessage(``);
    } catch (err) {
      const errMsg = err instanceof Error ? err.message : String(err);
      const errMsgFull = `Invalid passkey user name: ${errMsg}`;
      setErrorMessage(errMsgFull);
      console.error(errMsgFull);
    }
  };

  return (
    <>
      <h1 className="flex flex-row justify-center text-4xl font-bold">
        Show WebAuthn Passkey
      </h1>

      <div className="flex h-full w-screen flex-row items-center justify-center p-3">
        <label htmlFor="passkeyUserName" className="mr-3">
          Passkey user name:
        </label>
        <input
          id="passkeyUserName"
          type="text"
          className="w-64 rounded border px-2 py-1"
          value={passkeyUserName}
          onChange={(e) => handlePasskeyUserNameChange(e.target.value)}
          placeholder="Enter your passkey user name"
        />
      </div>

      <div className="m-3 flex h-full w-screen flex-row items-center justify-evenly">
        <button
          className="rounded bg-blue-500 px-4 py-2 font-bold text-white hover:bg-blue-700"
          onClick={registerWebAuthn}
        >
          Register WithWebAuthn
        </button>
        <button
          className="rounded bg-blue-500 px-4 py-2 font-bold text-white hover:bg-blue-700"
          onClick={() => {
            authenticateWebAuthn(selectedCredentialId);
          }}
        >
          Authenticate WithWebAuthn
        </button>
      </div>

      <div className="min-h-6">
        {errorMessage && (
          <div className="text-sm text-red-600">{errorMessage}</div>
        )}
      </div>

      <div
        id="passkeyItems"
        className="flex h-full w-screen flex-col items-center justify-center space-y-3"
      >
        <PasskeyItems
          darkMode={false}
          webAuthnItems={webAuthnItems}
          deleteItem={deleteItem}
          onSelect={setSelectedCredentialId}
          selectedCredentialId={selectedCredentialId}
        />
      </div>
    </>
  );
}

export default App;
