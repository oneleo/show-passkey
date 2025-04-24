// utils/bytes.ts
import type { HexString } from "./types";

/**
 * Checks if a string is a valid hexadecimal representation
 */
export function isHex(data: string): boolean {
  if (!data) return false;
  return /^(0x)?[0-9A-Fa-f]+$/.test(data);
}

/**
 * Converts various input types to a Uint8Array
 */
export function fromAny(
  data: Buffer | Uint8Array | HexString | null | undefined
): Uint8Array {
  if (data == null) {
    return new Uint8Array(0);
  }

  if (typeof data === "string") {
    // Handle hex string
    if (isHex(data)) {
      const hexString = data.startsWith("0x") ? data.slice(2) : data;
      const bytes = new Uint8Array(hexString.length / 2);
      for (let i = 0; i < hexString.length; i += 2) {
        bytes[i / 2] = parseInt(hexString.substr(i, 2), 16);
      }
      return bytes;
    }
    // Handle plain text
    return new TextEncoder().encode(data);
  }

  // Handle Buffer or Uint8Array
  return new Uint8Array(data);
}

/**
 * Concatenates two or more Uint8Arrays
 */
export function concat(...arrays: Uint8Array[]): Uint8Array {
  // Calculate total length
  const totalLength = arrays.reduce((acc, arr) => acc + arr.length, 0);
  const result = new Uint8Array(totalLength);

  // Fill data sequentially
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }

  return result;
}

/**
 * Converts a Uint8Array to a string with the specified encoding
 */
export function toString(
  bytes: Uint8Array,
  encoding: BufferEncoding = "utf8"
): string {
  // Special handling for base64url encoding
  if (encoding === "base64url") {
    let base64 = "";
    if (typeof btoa === "function") {
      // Browser environment
      const binary = Array.from(bytes)
        .map((byte) => String.fromCharCode(byte))
        .join("");
      base64 = btoa(binary);
    } else {
      // Node.js environment
      base64 = Buffer.from(bytes).toString("base64");
    }

    return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  // Handle hex encoding
  if (encoding === "hex") {
    let hexString = "";
    for (const byte of bytes) {
      hexString += byte.toString(16).padStart(2, "0");
    }
    return `0x${hexString}`;
  }

  // Handle utf8
  if (encoding === "utf8" || encoding === "utf-8") {
    return new TextDecoder().decode(bytes);
  }

  // Other encodings
  return Buffer.from(bytes).toString(encoding);
}
