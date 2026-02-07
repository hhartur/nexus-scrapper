import { Hono } from 'hono'
import { cors } from 'hono/cors'

/* ===============================
   App
================================ */
const app = new Hono()
app.use('*', cors())

/* ===============================
   Helpers base64 (Workers-safe)
================================ */
function base64ToUint8(base64) {
  const binary = atob(base64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}

function base64UrlDecode(str) {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/')
  while (base64.length % 4) base64 += '='
  return atob(base64)
}

/* ===============================
   Orion Crypto v2
================================ */
const ORION_SECRET = 'OrionNexus2025CryptoKey!Secure'

class OrionCrypto {
  constructor() {
    this.keys = []
    this.initialized = false
  }

  async initFromSecret(secret) {
    const keys = []
    for (let n = 0; n < 5; n++) {
      const keyString = `_orion_key_${n}_v2_${secret}`
      const encoded = new TextEncoder().encode(keyString)
      const hashBuffer = await crypto.subtle.digest('SHA-256', encoded)
      const hashArray = new Uint8Array(hashBuffer)
      const hexHash = Array.from(hashArray)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('')
      keys.push(hexHash)
    }
    this.init(keys)
    console.log('✅ Orion Crypto v2 inicializado')
  }

  init(keys) {
    this.keys = keys.map(keyHex => {
      const keyData = {
        key: new Uint8Array(
          keyHex.match(/.{1,2}/g).map(h => parseInt(h, 16))
        ),
        sbox: new Uint8Array(256),
        rsbox: new Uint8Array(256),
      }
      this.initSBoxForKey(keyData)
      return keyData
    })
    this.initialized = true
  }

  initSBoxForKey(keyData) {
    const key = keyData.key
    for (let i = 0; i < 256; i++) keyData.sbox[i] = i

    let j = 0
    for (let i = 0; i < 256; i++) {
      j = (j + keyData.sbox[i] + key[i % key.length]) % 256
      ;[keyData.sbox[i], keyData.sbox[j]] = [keyData.sbox[j], keyData.sbox[i]]
    }

    for (let i = 0; i < 256; i++) {
      keyData.rsbox[keyData.sbox[i]] = i
    }
  }

  rotateRight(byte, positions) {
    positions %= 8
    return ((byte >>> positions) | (byte << (8 - positions))) & 255
  }

  decrypt(keyIndex, encryptedBase64) {
    const keyData = this.keys[keyIndex]
    const key = keyData.key
    const rsbox = keyData.rsbox

    const encrypted = base64ToUint8(encryptedBase64)
    const decrypted = new Uint8Array(encrypted.length)
    const keyLength = key.length

    for (let i = encrypted.length - 1; i >= 0; i--) {
      let byte = encrypted[i]

      if (i > 0) byte ^= encrypted[i - 1]
      else byte ^= key[keyLength - 1]

      byte = rsbox[byte]

      const rotateAmount =
        (((key[(i + 3) % keyLength] + (i & 255)) & 255) % 7) + 1
      byte = this.rotateRight(byte, rotateAmount)

      byte ^= key[i % keyLength]

      decrypted[i] = byte
    }

    return new TextDecoder().decode(decrypted)
  }

  isEncryptedResponse(data) {
    return (
      data &&
      typeof data === 'object' &&
      typeof data.d === 'string' &&
      typeof data.k === 'number' &&
      typeof data.v === 'number'
    )
  }

  processResponse(response) {
    if (!this.isEncryptedResponse(response)) return response
    const keyIndex = response.v === 1 ? 0 : response.k || 0
    return JSON.parse(this.decrypt(keyIndex, response.d))
  }
}

/* ===============================
   Chapter XOR Crypto
================================ */
const CHAPTER_KEY = 'NexusToons2026SecretKeyForChapterEncryption!@#$'

function xorDecrypt(text, key) {
  let result = ''
  for (let i = 0; i < text.length; i++) {
    result += String.fromCharCode(
      text.charCodeAt(i) ^ key.charCodeAt(i % key.length)
    )
  }
  return result
}

function decryptChapter(encryptedBase64) {
  const decoded = base64UrlDecode(encryptedBase64)
  const decrypted = xorDecrypt(decoded, CHAPTER_KEY)
  return JSON.parse(decrypted)
}

/* ===============================
   Init Crypto
================================ */
const orionCrypto = new OrionCrypto()
await orionCrypto.initFromSecret(ORION_SECRET)

/* ===============================
   Helper
================================ */
function processApiResponse(data) {
  if (orionCrypto.isEncryptedResponse(data)) {
    return orionCrypto.processResponse(data)
  }

  if (typeof data === 'string') {
    return decryptChapter(data)
  }

  if (data?.d && typeof data.d === 'string') {
    try {
      return decryptChapter(data.d)
    } catch {
      return data
    }
  }

  return data
}

/* ===============================
   Routes
================================ */
app.get('/search', async c => {
  const query = c.req.query('query')
  const limit = c.req.query('limit') ?? 15
  const includeNsfw = c.req.query('includeNsfw') ?? true
  const sortBy = c.req.query('sortBy') ?? 'views'

  let url = `https://nexustoons.com/api/mangas?limit=${limit}&includeNsfw=${includeNsfw}&sortBy=${sortBy}`
  if (query) {
    url = `https://nexustoons.com/api/mangas?search=${encodeURIComponent(
      query
    )}&limit=${limit}&includeNsfw=${includeNsfw}`
  }

  const res = await fetch(url)
  const raw = await res.json()
  return c.json(processApiResponse(raw))
})

app.get('/manga/:slug', async c => {
  const res = await fetch(
    `https://nexustoons.com/api/manga/${c.req.param('slug')}`
  )
  const raw = await res.json()
  return c.json(processApiResponse(raw))
})

app.get('/chapter/:id', async c => {
  const token = c.req.header('authorization')
  const headers = token ? { Authorization: token } : {}

  const res = await fetch(
    `https://nexustoons.com/api/chapter/${c.req.param('id')}`,
    { headers }
  )
  const raw = await res.json()
  return c.json(processApiResponse(raw))
})

/* ===============================
   Export (ESSENCIAL)
================================ */
export default app
