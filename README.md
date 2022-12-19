# Svix Webhooks Web Crypto

Works in Cloudflare Workers, Deno, and >= Node.js 16.

[Same usage as offical library](https://docs.svix.com/receiving/verifying-payloads/how#verifying-using-our-official-libraries) except all methods are async and `new Webhook(secret)` is replaced by `await Webhook(secret)`

## Setup

[Install Deno](https://deno.land/manual@v1.29.1/getting_started/installation) then run `deno task build`

## Node.js Compatability

This library depends on the [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API). Node.js >= 19 is supported natively. Node 16 - 18 can be supported by either:

- Ideally, Run Node.js with the `--experimental-global-webcrypto` flag
- At your own risk, use a `SubtleCrypto` polyfill like [`@peculiar/webcrypto`](https://github.com/PeculiarVentures/webcrypto)
    ```typescript
    import { Crypto } from "@peculiar/webcrypto";

    const wh = await Webhook(secret, new Crypto().subtle);
    ```

