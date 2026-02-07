// server.js - COMPLETO COM AMBAS CRIPTOGRAFIAS
import Fastify from "fastify";
import path from "path";
import fs from "fs";
import archiver from "archiver";
import cors from "@fastify/cors";
import fastifyStatic from "@fastify/static";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const fastify = Fastify({ logger: true });

// ===============================
// Orion Crypto v2 (Mangas/API geral)
// ===============================
const ORION_SECRET = "OrionNexus2025CryptoKey!Secure";

class OrionCrypto {
  constructor() {
    this.keys = [];
    this.initialized = false;
  }

  async initFromSecret(secret) {
    const keys = [];
    for (let n = 0; n < 5; n++) {
      const keyString = `_orion_key_${n}_v2_${secret}`;
      const encoded = new TextEncoder().encode(keyString);
      const hashBuffer = await crypto.subtle.digest("SHA-256", encoded);
      const hashArray = new Uint8Array(hashBuffer);
      const hexHash = Array.from(hashArray)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
      keys.push(hexHash);
    }
    this.init(keys);
    console.log("✅ Orion Crypto v2 inicializado");
  }

  init(keys) {
    this.keys = keys.map((keyHex) => {
      const keyData = {
        key: new Uint8Array(
          keyHex.match(/.{1,2}/g).map((h) => parseInt(h, 16)),
        ),
        sbox: new Uint8Array(256),
        rsbox: new Uint8Array(256),
      };
      this.initSBoxForKey(keyData);
      return keyData;
    });
    this.initialized = true;
  }

  initSBoxForKey(keyData) {
    const key = keyData.key;
    for (let i = 0; i < 256; i++) keyData.sbox[i] = i;

    let j = 0;
    for (let i = 0; i < 256; i++) {
      j = (j + keyData.sbox[i] + key[i % key.length]) % 256;
      [keyData.sbox[i], keyData.sbox[j]] = [keyData.sbox[j], keyData.sbox[i]];
    }

    for (let i = 0; i < 256; i++) {
      keyData.rsbox[keyData.sbox[i]] = i;
    }
  }

  rotateRight(byte, positions) {
    positions = positions % 8;
    return ((byte >>> positions) | (byte << (8 - positions))) & 255;
  }

  decrypt(keyIndex, encryptedBase64) {
    const keyData = this.keys[keyIndex];
    const key = keyData.key;
    const rsbox = keyData.rsbox;

    const decoded = Buffer.from(encryptedBase64, "base64");
    const encrypted = new Uint8Array(decoded);
    const decrypted = new Uint8Array(encrypted.length);
    const keyLength = key.length;

    for (let i = encrypted.length - 1; i >= 0; i--) {
      let byte = encrypted[i];

      if (i > 0) byte ^= encrypted[i - 1];
      else byte ^= key[keyLength - 1];

      byte = rsbox[byte];

      const rotateAmount =
        (((key[(i + 3) % keyLength] + (i & 255)) & 255) % 7) + 1;
      byte = this.rotateRight(byte, rotateAmount);

      byte ^= key[i % keyLength];

      decrypted[i] = byte;
    }

    return new TextDecoder().decode(decrypted);
  }

  isEncryptedResponse(data) {
    if (!data || typeof data !== "object") return false;
    return (
      typeof data.d === "string" &&
      typeof data.k === "number" &&
      typeof data.v === "number" &&
      (data.v === 1 || data.v === 2)
    );
  }

  processResponse(response) {
    if (!this.isEncryptedResponse(response)) {
      return response;
    }

    const keyIndex = response.v === 1 ? 0 : response.k || 0;
    const decryptedJson = this.decrypt(keyIndex, response.d);
    return JSON.parse(decryptedJson);
  }
}

// ===============================
// Chapter XOR Crypto
// ===============================
const CHAPTER_KEY = "NexusToons2026SecretKeyForChapterEncryption!@#$";

function xorDecrypt(text, key) {
  let result = "";
  for (let i = 0; i < text.length; i++) {
    result += String.fromCharCode(
      text.charCodeAt(i) ^ key.charCodeAt(i % key.length),
    );
  }
  return result;
}

function base64UrlDecode(str) {
  let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4) base64 += "=";
  return Buffer.from(base64, "base64").toString("binary");
}

function decryptChapter(encryptedBase64) {
  try {
    const decoded = base64UrlDecode(encryptedBase64);
    const decrypted = xorDecrypt(decoded, CHAPTER_KEY);
    return JSON.parse(decrypted);
  } catch (error) {
    throw new Error(`Erro ao descriptografar capítulo: ${error.message}`);
  }
}

// Inicializa Orion Crypto
const orionCrypto = new OrionCrypto();
await orionCrypto.initFromSecret(ORION_SECRET);

// ===============================
// Plugins
// ===============================
await fastify.register(cors, { origin: true });
await fastify.register(fastifyStatic, {
  root: path.join(__dirname, "public"),
  prefix: "/",
});

// ===============================
// Helper para processar resposta
// ===============================
function processApiResponse(data, logger) {
  // Tenta Orion Crypto primeiro
  if (orionCrypto.isEncryptedResponse(data)) {
    logger.info(
      { k: data.k, v: data.v },
      "Descriptografando com Orion Crypto v2",
    );
    return orionCrypto.processResponse(data);
  }

  // Se for string simples, tenta XOR
  if (typeof data === "string") {
    logger.info("Descriptografando com Chapter XOR");
    return decryptChapter(data);
  }

  // Se tiver campo 'd' mas não for Orion, tenta XOR no 'd'
  if (data && typeof data === "object" && typeof data.d === "string") {
    logger.info("Tentando XOR no campo 'd'");
    try {
      return decryptChapter(data.d);
    } catch (e) {
      logger.warn("XOR falhou, retornando dados originais");
    }
  }

  // Retorna como está
  return data;
}

// ===============================
// SEARCH — mangas
// ===============================
fastify.get("/search", async (request, reply) => {
  const {
    query,
    limit = 15,
    includeNsfw = true,
    sortBy = "views",
  } = request.query;

  let url = `https://nexustoons.com/api/mangas?limit=${limit}&includeNsfw=${includeNsfw}&sortBy=${sortBy}`;

  if (query) {
    url = `https://nexustoons.com/api/mangas?search=${encodeURIComponent(query)}&limit=${limit}&includeNsfw=${includeNsfw}`;
  }

  try {
    const response = await fetch(url);
    const raw = await response.json();
    const decrypted = processApiResponse(raw, request.log);
    return decrypted;
  } catch (err) {
    fastify.log.error(err);
    return reply.status(500).send({ error: "Erro ao buscar mangás" });
  }
});

// ===============================
// Manga details
// ===============================
fastify.get("/manga/:slug", async (request, reply) => {
  try {
    const response = await fetch(
      `https://nexustoons.com/api/manga/${request.params.slug}`,
    );
    const raw = await response.json();
    const decrypted = processApiResponse(raw, request.log);
    return decrypted;
  } catch (err) {
    fastify.log.error(err);
    return reply.status(500).send({ error: "Erro ao buscar mangá" });
  }
});

// ===============================
// Chapter
// ===============================
fastify.get("/chapter/:id", async (request, reply) => {
  try {
    const headers = { "Content-Type": "application/json" };
    const token = request.headers.authorization?.replace("Bearer ", "");
    if (token) headers.Authorization = `Bearer ${token}`;

    const response = await fetch(
      `https://nexustoons.com/api/chapter/${request.params.id}`,
      { headers },
    );

    const raw = await response.json();

    request.log.info(
      {
        type: typeof raw,
        hasD: !!raw?.d,
        hasK: !!raw?.k,
        hasV: !!raw?.v,
      },
      "Resposta do capítulo",
    );

    const decrypted = processApiResponse(raw, request.log);
    return decrypted;
  } catch (err) {
    fastify.log.error(err);
    return reply.status(500).send({ error: "Erro ao buscar capítulo" });
  }
});

// ===============================
// Login
// ===============================
/*fastify.post("/login", async (request, reply) => {
  try {
    const response = await fetch("https://nexustoons.com/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request.body),
    });

    const data = await response.json();
    if (!response.ok) return reply.status(response.status).send(data);
    return data;
  } catch (err) {
    fastify.log.error(err);
    return reply.status(500).send({ error: "Erro ao fazer login" });
  }
});*/

// ===============================
// Download chapters
// ===============================
/*fastify.post("/download", async (request, reply) => {
  const { mangaSlug, mangaTitle, chapterIds } = request.body;

  if (!chapterIds?.length) {
    return reply.status(400).send({ error: "Nenhum capítulo selecionado" });
  }

  const tempDir = path.join(__dirname, "temp", `${mangaSlug}_${Date.now()}`);
  fs.mkdirSync(tempDir, { recursive: true });

  try {
    for (const chapterId of chapterIds) {
      const res = await fetch(
        `https://nexustoons.com/api/chapter/${chapterId}`,
      );
      const raw = await res.json();

      // Descriptografa o capítulo
      const chapter = processApiResponse(raw, fastify.log);

      if (["vip", "vip_timed"].includes(chapter.accessLevel)) continue;

      const chapterDir = path.join(tempDir, `Capitulo_${chapter.number}`);
      fs.mkdirSync(chapterDir, { recursive: true });

      for (const page of chapter.pages) {
        const img = await fetch(page.imageUrl);
        const buffer = Buffer.from(await img.arrayBuffer());
        const fileName = `pagina_${String(page.pageNumber).padStart(3, "0")}.webp`;
        fs.writeFileSync(path.join(chapterDir, fileName), buffer);
      }
    }

    const downloadsDir = path.join(__dirname, "downloads");
    fs.mkdirSync(downloadsDir, { recursive: true });

    const zipPath = path.join(downloadsDir, `${mangaSlug}.zip`);
    const output = fs.createWriteStream(zipPath);
    const archive = archiver("zip", { zlib: { level: 9 } });

    archive.pipe(output);
    archive.directory(tempDir, mangaTitle);
    await archive.finalize();

    await new Promise((res, rej) => {
      output.on("close", res);
      output.on("error", rej);
    });

    fs.rmSync(tempDir, { recursive: true, force: true });

    return {
      success: true,
      downloadUrl: `/downloads/${mangaSlug}.zip`,
      fileName: `${mangaSlug}.zip`,
    };
  } catch (err) {
    fastify.log.error(err);
    return reply.status(500).send({ error: "Erro ao criar download" });
  }
});*/

// ===============================
// Start
// ===============================
try {
  await fastify.listen({ port: 3001, host: "0.0.0.0" });
  console.log("🔥 Servidor rodando em http://localhost:3001");
  console.log("✅ Orion Crypto v2: ATIVO");
  console.log("✅ Chapter XOR Crypto: ATIVO");
} catch (err) {
  fastify.log.error(err);
  process.exit(1);
}
