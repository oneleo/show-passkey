import { DateTime } from "luxon";

import type { WebAuthnItem } from "../utils";
import { authenticators } from "../utils";

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
  return webAuthnItems.map((item) => {
    const defaultAaguid = `00000000-0000-0000-0000-000000000000`;

    const { aaguid, credentialId, browser, os, user } = item;

    const created = DateTime.fromMillis(item.timestamp).toUTC().toISO();
    const lastUsed = DateTime.fromMillis(item.lastUsed).toUTC().toISO();

    const authenticator =
      authenticators[aaguid] ?? authenticators[defaultAaguid];

    const {
      name: authenticatorName,
      icon_dark: darkIcon,
      icon_light: lightIcon,
    } = authenticator;

    return (
      <div
        key={credentialId}
        className={`flex w-[600px] cursor-pointer items-center justify-start rounded-lg border ${
          credentialId === selectedCredentialId
            ? "border-blue-600 bg-blue-100"
            : "hover:bg-gray-200"
        }`}
        onClick={() => onSelect(credentialId)}
      >
        <div className="m-3 flex w-32 items-center justify-center">
          {darkMode ? (
            <img src={darkIcon ?? undefined} />
          ) : (
            <img src={lightIcon ?? undefined} />
          )}
        </div>

        <div className="m-1 flex h-[150px] w-[390px] flex-col items-start justify-center space-y-1">
          <span className="text-lg font-semibold text-gray-900">
            {authenticatorName}
          </span>
          <span className="text-sm text-gray-600">User: {user}</span>
          <span className="text-sm text-gray-600">Created: {created}</span>
          <span className="text-sm text-gray-600">
            With: {browser} on {os}
          </span>
          <span className="text-sm text-gray-600">LastUsed: {lastUsed}</span>
        </div>

        <button
          onClick={(e) => {
            e.stopPropagation(); // Avoid triggering onSelect when clicking an icon
            deleteItem(credentialId);
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
  });
};
