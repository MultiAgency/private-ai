// End-to-end encryption to an attested model key, NEAR AI Cloud's E2EE v2:
// X25519 ECDH, HKDF-SHA256 and XChaCha20-Poly1305. Each encrypted field is hex
// of [ephemeral public key (32)][nonce (24)][ciphertext + tag]. With
// `X-Encrypt-All-Fields`, tool definitions and tool calls are encrypted too, so
// the gateway relays nothing readable but roles, ids and token counts.
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes, hexToBytes, randomBytes } from "@noble/hashes/utils.js";

const INFO = new TextEncoder().encode("ed25519_encryption");
const symmetricKey = shared => hkdf(sha256, shared, undefined, INFO, 32);

export function seal(plaintext, recipientX25519) {
  const ephemeral = x25519.utils.randomSecretKey();
  const nonce = randomBytes(24);
  const ciphertext = xchacha20poly1305(symmetricKey(x25519.getSharedSecret(ephemeral, recipientX25519)), nonce)
    .encrypt(new TextEncoder().encode(plaintext));
  return bytesToHex(concatBytes(x25519.getPublicKey(ephemeral), nonce, ciphertext));
}

export function open(hex, secretX25519) {
  const data = hexToBytes(hex);
  const key = symmetricKey(x25519.getSharedSecret(secretX25519, data.subarray(0, 32)));
  return new TextDecoder().decode(xchacha20poly1305(key, data.subarray(32, 56)).decrypt(data.subarray(56)));
}

/** One review's keys: a fresh client key pair, and the model's verified Ed25519 key. */
export function session(modelPublicKeyHex) {
  const clientSecret = ed25519.utils.randomSecretKey();
  const modelX25519 = ed25519.utils.toMontgomery(hexToBytes(modelPublicKeyHex));
  const clientX25519 = ed25519.utils.toMontgomerySecret(clientSecret);
  const encrypt = text => seal(text, modelX25519);
  const decrypt = hex => open(hex, clientX25519);

  return {
    headers: {
      "x-signing-algo": "ed25519",
      "x-client-pub-key": bytesToHex(ed25519.getPublicKey(clientSecret)),
      "x-model-pub-key": modelPublicKeyHex,
      "x-encryption-version": "2",
      "x-encrypt-all-fields": "true",
    },

    /** Encrypts every field the all-fields mode covers; the caller keeps the plaintext. */
    encryptRequest({ messages, tools }) {
      return {
        messages: messages.map(m => ({
          ...m,
          ...(m.content != null && { content: encrypt(m.content) }),
          ...(m.tool_calls && { tool_calls: m.tool_calls.map(c => encryptCall(c, encrypt)) }),
        })),
        tools: tools.map(t => ({
          type: t.type,
          function: {
            name: encrypt(t.function.name),
            description: encrypt(t.function.description),
            parameters: encrypt(JSON.stringify(t.function.parameters)),
          },
        })),
      };
    },

    /**
     * The reply a stream carries. Each fragment of each field is encrypted on its
     * own, so fragments are opened before they are joined: text fields by
     * concatenation, tool calls by their index (id and name come first, the
     * arguments in pieces after).
     */
    decryptStream(events) {
      const message = { role: "assistant", content: "", reasoning_content: "" };
      const calls = [];
      let finishReason = null;
      let usage = null;
      for (const event of events) {
        if (event.usage) usage = event.usage;
        const [choice] = event.choices ?? [];
        if (!choice) continue;
        if (choice.finish_reason) finishReason = choice.finish_reason;
        const delta = choice.delta ?? {};
        for (const field of ["content", "reasoning_content", "reasoning", "refusal"]) {
          if (delta[field]) message[field] = (message[field] ?? "") + decrypt(delta[field]);
        }
        for (const part of delta.tool_calls ?? []) {
          const call = (calls[part.index] ??= { id: "", type: "function", function: { name: "", arguments: "" } });
          if (part.id) call.id = part.id;
          if (part.function?.name) call.function.name += decrypt(part.function.name);
          if (part.function?.arguments) call.function.arguments += decrypt(part.function.arguments);
        }
      }
      if (calls.length) message.tool_calls = calls.filter(Boolean);
      return { id: events[0]?.id, message, finishReason, usage };
    },

    decryptMessage(message) {
      const plain = { ...message };
      for (const field of ["content", "reasoning_content", "reasoning", "refusal"]) {
        if (message[field]) plain[field] = decrypt(message[field]);
      }
      if (message.tool_calls) plain.tool_calls = message.tool_calls.map(c => encryptCall(c, decrypt));
      return plain;
    },
  };
}

const encryptCall = (call, transform) => ({
  ...call,
  function: { name: transform(call.function.name), arguments: transform(call.function.arguments) },
});
