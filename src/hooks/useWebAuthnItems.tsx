import { useEffect, useState } from "react";
import type { B64UrlString, WebAuthnItem } from "../utils";

const WEB_AUTHN_ITEMS_STORAGE_KEY = "webAuthnItems";

export function useWebAuthnItems() {
  const [webAuthnItems, setWebAuthnItems] = useState<WebAuthnItem[]>([]);
  const [initialized, setInitialized] = useState(false);

  useEffect(() => {
    const stored = localStorage.getItem(WEB_AUTHN_ITEMS_STORAGE_KEY);
    if (stored) {
      try {
        setWebAuthnItems(JSON.parse(stored));
      } catch (err) {
        const errMsg = err instanceof Error ? err.message : String(err);
        const errMsgFull = `Failed to parse webAuthnItems from localStorage: ${errMsg}`;
        console.error(errMsgFull);
      }
    }
    setInitialized(true);
  }, []);

  useEffect(() => {
    if (!initialized) {
      return;
    }
    localStorage.setItem(
      WEB_AUTHN_ITEMS_STORAGE_KEY,
      JSON.stringify(webAuthnItems),
    );
  }, [webAuthnItems]);

  const addItem = (item: WebAuthnItem) => {
    setWebAuthnItems((prev) => {
      const exists = prev.some(
        (existing) => existing.credentialId === item.credentialId,
      );
      if (exists) {
        console.warn(
          `Credential with ID ${item.credentialId} already exists. Skipping add.`,
        );
        return prev;
      }
      return [...prev, item];
    });
  };

  const updateItem = (
    updated: Partial<WebAuthnItem> & { credentialId: B64UrlString },
  ) => {
    setWebAuthnItems((prev) =>
      prev.map((item) =>
        item.credentialId === updated.credentialId
          ? { ...item, ...updated }
          : item,
      ),
    );
  };

  const deleteItem = (credentialId: string) => {
    setWebAuthnItems((prev) =>
      prev.filter((item) => item.credentialId !== credentialId),
    );
  };

  return {
    webAuthnItems,
    addItem,
    updateItem,
    deleteItem,
  };
}
