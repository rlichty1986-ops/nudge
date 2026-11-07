// Runs every minute: sends a push for every reminder that has come due on any registered device.
import type { Config, Context } from "@netlify/functions"
import crypto from "node:crypto"
import { getStore } from "@netlify/blobs"

// ---------- shared helpers (push encryption + storage) ----------
// Minimal Web Push sender (RFC 8291 aes128gcm encryption + RFC 8292 VAPID), using only node:crypto.

type Vapid = { publicKey: string; privateJwk: crypto.JsonWebKey }
type PushSubscriptionJSON = { endpoint: string; keys: { p256dh: string; auth: string } }

const b64u = (buf: Buffer) => buf.toString("base64url")
const fromB64u = (s: string) => Buffer.from(s, "base64url")
const hmac = (key: Buffer, data: Buffer) => crypto.createHmac("sha256", key).update(data).digest()
const hkdfExpand = (prk: Buffer, info: Buffer, len: number) => hmac(prk, Buffer.concat([info, Buffer.from([1])])).subarray(0, len)

function generateVapid(): Vapid {
  const { privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
  const jwk = privateKey.export({ format: "jwk" })
  const pub = Buffer.concat([Buffer.from([4]), fromB64u(jwk.x as string), fromB64u(jwk.y as string)])
  return { publicKey: b64u(pub), privateJwk: jwk }
}

function encrypt(payload: string, p256dh: string, auth: string): Buffer {
  const uaPublic = fromB64u(p256dh)
  const authSecret = fromB64u(auth)
  const ecdh = crypto.createECDH("prime256v1")
  const asPublic = ecdh.generateKeys()
  const shared = ecdh.computeSecret(uaPublic)
  const salt = crypto.randomBytes(16)

  const prkKey = hmac(authSecret, shared)
  const ikm = hkdfExpand(prkKey, Buffer.concat([Buffer.from("WebPush: info\0"), uaPublic, asPublic]), 32)
  const prk = hmac(salt, ikm)
  const cek = hkdfExpand(prk, Buffer.from("Content-Encoding: aes128gcm\0"), 16)
  const nonce = hkdfExpand(prk, Buffer.from("Content-Encoding: nonce\0"), 12)

  const cipher = crypto.createCipheriv("aes-128-gcm", cek, nonce)
  const body = Buffer.concat([cipher.update(Buffer.concat([Buffer.from(payload, "utf8"), Buffer.from([2])])), cipher.final(), cipher.getAuthTag()])

  const header = Buffer.alloc(21)
  salt.copy(header, 0)
  header.writeUInt32BE(4096, 16)
  header[20] = asPublic.length
  return Buffer.concat([header, asPublic, body])
}

function vapidHeader(endpoint: string, vapid: Vapid, subject: string): string {
  const aud = new URL(endpoint).origin
  const head = b64u(Buffer.from(JSON.stringify({ typ: "JWT", alg: "ES256" })))
  const claims = b64u(Buffer.from(JSON.stringify({ aud, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: subject })))
  const key = crypto.createPrivateKey({ key: vapid.privateJwk, format: "jwk" })
  const sig = crypto.sign("sha256", Buffer.from(`${head}.${claims}`), { key, dsaEncoding: "ieee-p1363" })
  return `vapid t=${head}.${claims}.${b64u(sig)}, k=${vapid.publicKey}`
}

async function sendPush(sub: PushSubscriptionJSON, payload: object, vapid: Vapid, subject: string): Promise<number> {
  const body = encrypt(JSON.stringify(payload), sub.keys.p256dh, sub.keys.auth)
  const res = await fetch(sub.endpoint, {
    method: "POST",
    headers: {
      "Content-Encoding": "aes128gcm",
      "Content-Type": "application/octet-stream",
      TTL: "86400",
      Urgency: "high",
      Authorization: vapidHeader(sub.endpoint, vapid, subject),
    },
    body,
  })
  if (res.status >= 400) console.log("push rejected", res.status, (await res.text().catch(() => "")).slice(0, 200))
  return res.status
}


type ScheduleEntry = { k: string; at: number; title: string; body: string }
type Device = { sub: PushSubscriptionJSON; schedule: ScheduleEntry[]; updated: number }

const store = () => getStore({ name: "nudge", consistency: "strong" })

const deviceKey = (endpoint: string) =>
  "devices/" + crypto.createHash("sha256").update(endpoint).digest("hex").slice(0, 40)

// VAPID keys are created automatically on first use and kept in Blobs, so there is nothing to configure.
async function getVapid(): Promise<Vapid> {
  const s = store()
  const existing = (await s.get("vapid", { type: "json" })) as Vapid | null
  if (existing) return existing
  const fresh = generateVapid()
  const { modified } = await s.setJSON("vapid", fresh, { onlyIfNew: true })
  return modified ? fresh : ((await s.get("vapid", { type: "json" })) as Vapid)
}

function subjectFor(siteUrl?: string): string {
  const url = siteUrl || Netlify.env.get("URL")
  return url && url.startsWith("https://") ? url : "mailto:nudge-app@users.noreply.github.com"
}

function cleanSubscription(raw: any): PushSubscriptionJSON | null {
  if (!raw || typeof raw.endpoint !== "string" || !raw.endpoint.startsWith("https://")) return null
  const { p256dh, auth } = raw.keys || {}
  if (typeof p256dh !== "string" || typeof auth !== "string") return null
  return { endpoint: raw.endpoint.slice(0, 1000), keys: { p256dh: p256dh.slice(0, 200), auth: auth.slice(0, 100) } }
}

function cleanSchedule(raw: any): ScheduleEntry[] {
  if (!Array.isArray(raw)) return []
  const now = Date.now()
  return raw
    .filter((x) => x && Number.isFinite(x.at) && x.at > now - 60_000 && x.at < now + 400 * 864e5)
    .slice(0, 400)
    .map((x) => ({ k: String(x.k ?? "").slice(0, 120), at: Number(x.at), title: String(x.title ?? "Nudge").slice(0, 140), body: String(x.body ?? "").slice(0, 240) }))
}

// ---------- function ----------

const LATE_LIMIT = 15 * 60_000 // skip anything more than 15 min stale (e.g. after an outage)

export default async (_req: Request, context: Context) => {
  const s = store()
  const now = Date.now()
  const vapid = await getVapid()
  const subject = subjectFor(context.site?.url)
  const { blobs } = await s.list({ prefix: "devices/" })

  let sent = 0
  await Promise.all(
    blobs.map(async ({ key }) => {
      const entry = await s.getWithMetadata(key, { type: "json" })
      if (entry === null) return
      const device = entry.data as Device
      const due = (device.schedule || []).filter((x) => x.at <= now)
      if (!due.length) return

      let gone = false
      for (const x of due.filter((x) => now - x.at < LATE_LIMIT).slice(-5)) {
        const status = await sendPush(device.sub, { title: x.title, body: x.body, tag: x.k }, vapid, subject)
        if (status === 404 || status === 410) { gone = true; break } // subscription expired / app removed
        if (status < 300) sent++
      }
      if (gone) { await s.delete(key); return }

      // Drop what we just handled. If the app re-synced meanwhile, keep its newer copy.
      await s.setJSON(key, { ...device, schedule: device.schedule.filter((x) => x.at > now) }, { onlyIfMatch: entry.etag })
    }),
  )
  if (sent) console.log(`sent ${sent} reminder(s)`)
}

export const config: Config = {
  schedule: "* * * * *", // every minute (UTC; timing is absolute so time zones don't matter)
}


