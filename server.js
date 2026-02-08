import { Hono } from 'hono'
import { cors } from 'hono/cors'
import ImageKit from 'imagekit-javascript'

const imagekit = new ImageKit({
  publicKey: 'public_jy+YNalWZalq1kwXGxEeUsscFBo=',
  privateKey: 'private_Ey90FTJijnuciUtq1X2TpVychMQ=',
  urlEndpoint: 'https://ik.imagekit.io/scrapper'
})

const uploadedImages = new Map()

const app = new Hono()
app.use('*', cors())

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

const orionCrypto = new OrionCrypto()
await orionCrypto.initFromSecret(ORION_SECRET)

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

app.get('/search', async c => {
  const query = c.req.query('query')
  const page = c.req.query('page') ?? 1
  const limit = c.req.query('limit') ?? 15
  const includeNsfw = c.req.query('includeNsfw') ?? true
  const sortBy = c.req.query('sortBy') ?? 'views'

  let url = `https://nexustoons.com/api/mangas?` +
            `page=${page}` +
            `&limit=${limit}` +
            `&includeNsfw=${includeNsfw}` +
            `&sortBy=${sortBy}`

  if (query) {
    url = `https://nexustoons.com/api/mangas?` +
          `search=${encodeURIComponent(query)}` +
          `&page=${page}` +
          `&limit=${limit}` +
          `&includeNsfw=${includeNsfw}`
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

app.get('/image', async c => {
  const url = c.req.query('url')
  if (!url) return c.text('missing url', 400)

  try {
    const imgRes = await fetch(url)
    if (!imgRes.ok) {
      return c.text('image fetch failed', 502)
    }

    const arrayBuffer = await imgRes.arrayBuffer()
    const uint8Array = new Uint8Array(arrayBuffer)
    
    let binary = ''
    const len = uint8Array.byteLength
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(uint8Array[i])
    }
    const base64Image = btoa(binary)

    const fileName = `temp_${Date.now()}_${Math.random().toString(36).substring(7)}`
    
    const formData = new FormData()
    formData.append('file', base64Image)
    formData.append('fileName', fileName)
    formData.append('folder', '/temp-images')
    formData.append('useUniqueFileName', 'true')
    formData.append('tags', 'temporary')

    const privateKey = 'private_Ey90FTJijnuciUtq1X2TpVychMQ='
    const publicKey = 'public_jy+YNalWZalq1kwXGxEeUsscFBo='
    const authHeader = 'Basic ' + btoa(privateKey + ':')

    const uploadResponse = await fetch('https://upload.imagekit.io/api/v1/files/upload', {
      method: 'POST',
      headers: {
        'Authorization': authHeader
      },
      body: formData
    })

    const uploadData = await uploadResponse.json()
    const imagekitUrl = uploadData.url
    const fileId = uploadData.fileId

    const deleteAfter = Math.floor(Math.random() * 20000) + 10000
    
    const timeoutId = setTimeout(async () => {
      try {
        await fetch(`https://api.imagekit.io/v1/files/${fileId}`, {
          method: 'DELETE',
          headers: {
            'Authorization': authHeader
          }
        })
        uploadedImages.delete(fileId)
      } catch (error) {
        console.error('Erro ao deletar imagem:', error)
      }
    }, deleteAfter)

    uploadedImages.set(fileId, {
      timeoutId,
      uploadedAt: Date.now(),
      deleteAt: Date.now() + deleteAfter
    })

    return c.redirect(imagekitUrl)

  } catch (error) {
    console.error('Erro:', error)
    return c.text('upload failed', 500)
  }
})

export default app