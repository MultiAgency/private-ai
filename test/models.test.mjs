// Which catalog entries `npm run models` tries to attest (core/models.mjs).
import assert from "node:assert/strict";
import test from "node:test";

import { chatModels } from "../core/models.mjs";

const model = (modelId, metadata = {}) => ({
  modelId,
  metadata: {
    verifiable: true,
    ownedBy: "nearai",
    contextLength: 131_072,
    architecture: { outputModalities: ["text"] },
    ...metadata,
  },
});

test("a verifiable NEAR-run text model with room for a pull request is listed", () => {
  assert.deepEqual(chatModels({ models: [model("z-ai/glm-5.3-flash")] }), ["z-ai/glm-5.3-flash"]);
});

test("the catalog may arrive as models, data or a bare array, and an entry may use id", () => {
  const entry = model("a/b");
  assert.deepEqual(chatModels({ models: [entry] }), ["a/b"]);
  assert.deepEqual(chatModels({ data: [entry] }), ["a/b"]);
  assert.deepEqual(chatModels([entry]), ["a/b"]);
  const { modelId, ...byId } = entry;
  assert.deepEqual(chatModels([{ ...byId, id: "c/d" }]), ["c/d"]);
});

test("models that are not verifiable, not NEAR's own, or too small are left out", () => {
  const list = [
    model("unverifiable", { verifiable: false }),
    model("someone-elses", { ownedBy: "other" }),
    model("tiny-context", { contextLength: 4096 }),
    model("no-context", { contextLength: undefined }),
    model("keeper"),
  ];
  assert.deepEqual(chatModels(list), ["keeper"]);
});

test("models that do not output text, and speech, filter or reranker models, are left out", () => {
  const list = [
    model("image-maker", { architecture: { outputModalities: ["image"] } }),
    model("no-architecture", { architecture: undefined }),
    model("acme/Reranker-8B"),
    model("acme/embed-v2"),
    model("openai/Whisper-large"),
    model("acme/safety-filter"),
    model("keeper"),
  ];
  assert.deepEqual(chatModels(list), ["keeper"]);
});

test("an empty catalog lists nothing", () => {
  assert.deepEqual(chatModels({ models: [] }), []);
});
