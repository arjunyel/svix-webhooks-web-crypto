// deno-lint-ignore-file no-explicit-any
import {
  assertEquals,
  assertRejects,
} from "https://deno.land/std@0.168.0/testing/asserts.ts";
import {
  decode,
  encode,
} from "https://deno.land/std@0.168.0/encoding/base64.ts";
import { Crypto } from "npm:@peculiar/webcrypto@1.4.1";

import { Webhook, WebhookVerificationError } from "./main.ts";

const defaultMsgID = "msg_p5jXN8AQM9LWM0D4loKWxJek";
const defaultPayload = `{"test": 2432232314}`;
const defaultSecret = "MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";

const tolerance_in_ms = 5 * 60 * 1000;

async function createTestPayload(timestamp = Date.now()) {
  const key = await globalThis.crypto.subtle.importKey(
    "raw",
    decode(defaultSecret),
    { name: "HMAC", hash: "SHA-256" },
    true,
    ["sign", "verify"],
  );

  const toSign = new globalThis.TextEncoder().encode(
    `${defaultMsgID}.${Math.floor(timestamp / 1000)}.${defaultPayload}`,
  );

  const signature = encode(
    new Uint8Array(await globalThis.crypto.subtle.sign("HMAC", key, toSign)),
  );
  return new TestPayload(signature, timestamp);
}

class TestPayload {
  public id: string;
  public timestamp: number;
  public header: Record<string, string>;
  public secret: string;
  public payload: string;
  public signature: string;

  public constructor(signature: string, timestamp: number) {
    this.id = defaultMsgID;
    this.timestamp = Math.floor(timestamp / 1000);

    this.payload = defaultPayload;
    this.secret = defaultSecret;
    this.signature = signature;

    this.header = {
      "svix-id": this.id,
      "svix-signature": "v1," + this.signature,
      "svix-timestamp": this.timestamp.toString(),
    };
  }
}

Deno.test("empty key raises error", () => {
  assertRejects(
    async () => await Webhook(""),
    Error,
    "Secret can't be empty.",
  );
  assertRejects(async () => await Webhook(undefined as any)),
    Error,
    "Secret can't be empty.";
  assertRejects(async () => await Webhook(null as any)),
    Error,
    "Secret can't be empty.";
});

Deno.test("missing id raises error", async () => {
  const wh = await Webhook(defaultSecret);

  const testPayload = await createTestPayload();
  delete testPayload.header["svix-id"];

  assertRejects(
    () => wh.verify(testPayload.payload, testPayload.header),
    WebhookVerificationError,
  );
});

Deno.test("missing timestamp raises error", async () => {
  const wh = await Webhook(defaultSecret);

  const testPayload = await createTestPayload();
  delete testPayload.header["svix-timestamp"];

  assertRejects(
    () => wh.verify(testPayload.payload, testPayload.header),
    WebhookVerificationError,
  );
});

Deno.test("invalid timestamp throws error", async () => {
  const wh = await Webhook(defaultSecret);

  const testPayload = await createTestPayload();
  testPayload.header["svix-timestamp"] = "hello";

  assertRejects(
    () => wh.verify(testPayload.payload, testPayload.header),
    WebhookVerificationError,
  );
});

Deno.test("missing signature raises error", async () => {
  const wh = await Webhook(defaultSecret);

  const testPayload = await createTestPayload();
  delete testPayload.header["svix-signature"];

  assertRejects(
    () => wh.verify(testPayload.payload, testPayload.header),
    WebhookVerificationError,
  );
});

Deno.test("invalid signature throws error", async () => {
  const wh = await Webhook(defaultSecret);

  const testPayload = await createTestPayload();
  testPayload.header["svix-signature"] = "v1,dawfeoifkpqwoekfpqoekf";

  assertRejects(
    () => wh.verify(testPayload.payload, testPayload.header),
    WebhookVerificationError,
  );
});

Deno.test("valid signature is valid and returns valid json", async () => {
  const wh = await Webhook(defaultSecret);

  const testPayload = await createTestPayload();

  wh.verify(testPayload.payload, testPayload.header);
});

Deno.test("valid unbranded signature is valid and returns valid json", async () => {
  const wh = await Webhook(defaultSecret);

  const testPayload = await createTestPayload();
  const unbrandedHeaders: Record<string, string> = {
    "webhook-id": testPayload.header["svix-id"],
    "webhook-signature": testPayload.header["svix-signature"],
    "webhook-timestamp": testPayload.header["svix-timestamp"],
  };
  testPayload.header = unbrandedHeaders;

  wh.verify(testPayload.payload, testPayload.header);
});

Deno.test("old timestamp fails", async () => {
  const wh = await Webhook(defaultSecret);

  const testPayload = await createTestPayload(
    Date.now() - tolerance_in_ms - 1000,
  );

  assertRejects(
    () => wh.verify(testPayload.payload, testPayload.header),
    WebhookVerificationError,
  );
});

Deno.test("new timestamp fails", async () => {
  const wh = await Webhook(defaultSecret);

  const testPayload = await createTestPayload(
    Date.now() + tolerance_in_ms + 1000,
  );

  assertRejects(
    () => wh.verify(testPayload.payload, testPayload.header),
    WebhookVerificationError,
  );
});

Deno.test("multi sig payload is valid", async () => {
  const wh = await Webhook(defaultSecret);

  const testPayload = await createTestPayload();
  const sigs = [
    "v1,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc=",
    "v2,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc=",
    testPayload.header["svix-signature"], // valid signature
    "v1,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc=",
  ];
  testPayload.header["svix-signature"] = sigs.join(" ");

  wh.verify(testPayload.payload, testPayload.header);
});

Deno.test("verification works with and without signature prefix", async () => {
  const testPayload = await createTestPayload();

  let wh = await Webhook(defaultSecret);
  wh.verify(testPayload.payload, testPayload.header);

  wh = await Webhook("whsec_" + defaultSecret);
  wh.verify(testPayload.payload, testPayload.header);
});

Deno.test("sign function works", async () => {
  const key = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
  const msgId = "msg_p5jXN8AQM9LWM0D4loKWxJek";
  const timestamp = new Date(1614265330 * 1000);
  const payload = '{"test": 2432232314}';
  const expected = "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=";

  const wh = await Webhook(key);

  const signature = await wh.sign(msgId, timestamp, payload);
  assertEquals(signature, expected);
});

Deno.test("Can polyfill Web Crypto requirement", async () => {
  const secret = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
  const msgId = "msg_p5jXN8AQM9LWM0D4loKWxJek";
  const timestamp = new Date(1614265330 * 1000);
  const payload = '{"test": 2432232314}';
  const expected = "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=";

  const wh = await Webhook(secret, new Crypto().subtle);

  const signature = await wh.sign(msgId, timestamp, payload);
  assertEquals(signature, expected);
});
