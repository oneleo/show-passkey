import { DateTime } from "luxon";
import { memo, useEffect, useMemo, useState } from "react";
import type { AuthenticatorData, WebAuthnItem } from "../utils";
import { getAuthenticatorData } from "../utils";

// Component for rendering an individual authenticator item
const AuthenticatorItem = memo(
  ({
    item,
    darkMode,
    isSelected,
    onSelect,
    onDelete,
  }: {
    item: WebAuthnItem & {
      createdAtIso: string | null;
      lastUsedIso: string | null;
    };
    darkMode: boolean;
    isSelected: boolean;
    onSelect: (credentialId: string) => void;
    onDelete: (credentialId: string) => void;
  }) => {
    const [authenticatorData, setAuthenticatorData] =
      useState<AuthenticatorData>();

    useEffect(() => {
      async function loadAuthenticator() {
        const data = await getAuthenticatorData(item.aaguid);
        if (data) {
          setAuthenticatorData(data);
          return;
        }

        // Fall back to default authenticator if specific one not found
        const defaultData = await getAuthenticatorData(
          `00000000-0000-0000-0000-000000000000`,
        );
        setAuthenticatorData(defaultData);
      }
      loadAuthenticator();
    }, [item.aaguid]);

    // Render nothing until data is loaded
    if (!authenticatorData) return null;

    return (
      <div
        className={`flex w-[600px] cursor-pointer items-center justify-start rounded-lg border ${
          isSelected ? "border-blue-600 bg-blue-100" : "hover:bg-gray-200"
        }`}
        onClick={() => onSelect(item.credentialId)}
      >
        {/* Authenticator icon */}
        <div className="m-3 flex w-32 items-center justify-center">
          <img
            src={
              darkMode
                ? (authenticatorData.icon_dark ?? undefined)
                : (authenticatorData.icon_light ?? undefined)
            }
            alt={`${authenticatorData.name} icon`}
          />
        </div>

        {/* Authenticator details */}
        <div className="m-1 flex h-[150px] w-[390px] flex-col items-start justify-center space-y-1">
          <span className="text-lg font-semibold text-gray-900">
            {authenticatorData.name}
          </span>
          <span className="text-sm text-gray-600">User: {item.user}</span>
          <span className="text-sm text-gray-600">
            Created: {item.createdAtIso ?? ``}
          </span>
          <span className="text-sm text-gray-600">
            With: {item.browser} on {item.os}
          </span>
          <span className="text-sm text-gray-600">
            LastUsed: {item.lastUsedIso ?? ``}
          </span>
        </div>

        {/* Delete button */}
        <button
          onClick={(e) => {
            e.stopPropagation(); // Prevent parent onClick from triggering
            onDelete(item.credentialId);
          }}
          className="text-gray-300 hover:text-gray-600"
        >
          <svg
            className="h-6 w-6"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
            xmlns="http://www.w3.org/2000/svg"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth="2"
              d="M6 18L18 6M6 6l12 12"
            />
          </svg>
        </button>
      </div>
    );
  },
);

export const PasskeyItems = ({
  darkMode,
  webAuthnItems,
  selectedCredentialId,
  deleteItem,
  onSelect,
}: {
  darkMode: boolean;
  webAuthnItems: WebAuthnItem[];
  selectedCredentialId?: string;
  deleteItem: (credentialId: string) => void;
  onSelect: (credentialId: string) => void;
}) => {
  // Pre-process items only when webAuthnItems changes
  const processedItems = useMemo(() => {
    const timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone;

    return webAuthnItems.map((item) => ({
      ...item,
      // Format timestamps to ISO with user's local timezone
      createdAtIso: item.createdAt
        ? DateTime.fromMillis(item.createdAt).toUTC().setZone(timeZone).toISO()
        : ``,
      lastUsedIso: item.lastUsed
        ? DateTime.fromMillis(item.lastUsed).toUTC().setZone(timeZone).toISO()
        : ``,
    }));
  }, [webAuthnItems]);

  return (
    <div>
      {processedItems.map((item) => (
        <AuthenticatorItem
          key={item.credentialId}
          item={item}
          darkMode={darkMode}
          isSelected={item.credentialId === selectedCredentialId}
          onSelect={onSelect}
          onDelete={deleteItem}
        />
      ))}
    </div>
  );
};
