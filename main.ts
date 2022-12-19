import {
  decode,
  encode,
} from "https://deno.land/std@0.168.0/encoding/base64.ts";
import { timingSafeEqual } from "https://deno.land/std@0.168.0/crypto/timing_safe_equal.ts";

class ExtendableError extends Error {
  constructor(message?: string) {
    super(message);
    Object.setPrototypeOf(this, ExtendableError.prototype);
    this.name = "ExtendableError";
    this.stack = new Error(message).stack;
  }
}

export class WebhookVerificationError extends ExtendableError {
  constructor(message: string) {
    super(message);
    Object.setPrototypeOf(this, WebhookVerificationError.prototype);
    this.name = "WebhookVerificationError";
  }
}

type WebhookRequiredHeaders = {
  "svix-id": string;
  "svix-timestamp": string;
  "svix-signature": string;
};

type WebhookUnbrandedRequiredHeaders = {
  "webhook-id": string;
  "webhook-timestamp": string;
  "webhook-signature": string;
};

function verifyTimestamp(timestampHeader: string): Date {
  const WEBHOOK_TOLERANCE_IN_SECONDS = 300; // 5 minutes
  const now = Math.floor(Date.now() / 1000);
  const timestamp = parseInt(timestampHeader, 10);
  if (isNaN(timestamp)) {
    throw new WebhookVerificationError("Invalid Signature Headers");
  }

  if (now - timestamp > WEBHOOK_TOLERANCE_IN_SECONDS) {
    throw new WebhookVerificationError("Message timestamp too old");
  }
  if (timestamp > now + WEBHOOK_TOLERANCE_IN_SECONDS) {
    throw new WebhookVerificationError("Message timestamp too new");
  }
  return new Date(timestamp * 1000);
}

class SvixWebhook {
  readonly #key: CryptoKey;
  readonly #crypto: SubtleCrypto;

  constructor(key: CryptoKey, subtleCryptoImpl: SubtleCrypto) {
    this.#key = key;
    this.#crypto = subtleCryptoImpl;
  }

  public async verify<T>(
    payload: string,
    headers_:
      | WebhookRequiredHeaders
      | WebhookUnbrandedRequiredHeaders
      | Record<string, string>,
  ): Promise<T> {
    const headers: Record<string, string> = {};
    for (const key of Object.keys(headers_)) {
      headers[key.toLowerCase()] = (headers_ as Record<string, string>)[key];
    }

    let msgId = headers["svix-id"];
    let msgSignature = headers["svix-signature"];
    let msgTimestamp = headers["svix-timestamp"];

    if (!msgSignature || !msgId || !msgTimestamp) {
      msgId = headers["webhook-id"];
      msgSignature = headers["webhook-signature"];
      msgTimestamp = headers["webhook-timestamp"];

      if (!msgSignature || !msgId || !msgTimestamp) {
        throw new WebhookVerificationError("Missing required headers");
      }
    }

    const timestamp = verifyTimestamp(msgTimestamp);

    const computedSignature = await this.sign(msgId, timestamp, payload);
    const expectedSignature = computedSignature.split(",")[1];

    const passedSignatures = msgSignature.split(" ");
    for (const versionedSignature of passedSignatures) {
      const [version, signature] = versionedSignature.split(",");
      if (version !== "v1") {
        continue;
      }

      const encoder = new globalThis.TextEncoder();

      if (
        timingSafeEqual(
          encoder.encode(signature),
          encoder.encode(expectedSignature),
        )
      ) {
        return JSON.parse(payload);
      }
    }
    throw new WebhookVerificationError("No matching signature found");
  }

  public async sign(
    msgId: string,
    timestamp: Date,
    payload: string,
  ): Promise<string> {
    const toSign = new globalThis.TextEncoder().encode(
      `${msgId}.${timestamp.getTime() / 1000}.${payload}`,
    );
    const expectedSignature = encode(
      new Uint8Array(await this.#crypto.sign("HMAC", this.#key, toSign)),
    );
    return `v1,${expectedSignature}`;
  }
}

export async function Webhook(
  secret: `whsec_${string}` | string,
  subtleCryptoImpl?: SubtleCrypto,
): Promise<SvixWebhook> {
  if (!secret || typeof secret !== "string") {
    throw new Error("Secret can't be empty.");
  }
  if (secret.startsWith("whsec_")) {
    secret = secret.substring(6);
  }
  // Use either polyfill or built-in
  subtleCryptoImpl = subtleCryptoImpl || globalThis.crypto.subtle;

  return new SvixWebhook(
    await subtleCryptoImpl.importKey(
      "raw",
      decode(secret),
      { name: "HMAC", hash: "SHA-256" },
      true,
      ["sign", "verify"],
    ),
    subtleCryptoImpl,
  );
}
