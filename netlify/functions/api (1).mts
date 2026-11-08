// Endpoints the app calls:
//   GET    /api/vapid  -> public key the browser needs to subscribe
//   POST   /api/sync   -> save this device's subscription + upcoming reminder times
//   DELETE /api/sync   -> forget this device
//   POST   /api/test   -> send a test notification right now
//   POST   /api/vault  -> PIN-protected cloud backup: save / load / recover
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

// ---------- cloud backup (PIN-protected, single owner) ----------
// The first PIN ever used on this site becomes the owner PIN. Backups and recovery need it.

type Owner = { salt: string; hash: string }
type Fails = { count: number; until: number }

async function checkPin(pin: unknown): Promise<"ok" | "wrong" | "locked"> {
  if (typeof pin !== "string" || pin.length < 4 || pin.length > 64) return "wrong"
  const s = store()
  const fails = ((await s.get("pin-fails", { type: "json" })) as Fails | null) || { count: 0, until: 0 }
  if (fails.until > Date.now()) return "locked"
  const owner = (await s.get("owner", { type: "json" })) as Owner | null
  if (!owner) {
    const salt = crypto.randomBytes(16).toString("hex")
    const hash = crypto.scryptSync(pin, salt, 32).toString("hex")
    const { modified } = await s.setJSON("owner", { salt, hash }, { onlyIfNew: true })
    if (modified) return "ok"
    return checkPin(pin)
  }
  const ok = crypto.timingSafeEqual(crypto.scryptSync(pin, owner.salt, 32), Buffer.from(owner.hash, "hex"))
  if (ok) {
    if (fails.count) await s.setJSON("pin-fails", { count: 0, until: 0 })
    return "ok"
  }
  const count = fails.count + 1
  await s.setJSON("pin-fails", { count: count >= 8 ? 0 : count, until: count >= 8 ? Date.now() + 15 * 60_000 : 0 })
  return "wrong"
}

// Rebuild reminders from the copies kept for push notifications (titles, times, repeats, heads-ups).
async function recoverFromSchedules() {
  const s = store()
  const { blobs } = await s.list({ prefix: "devices/" })
  const byId = new Map<string, { id: string; occ: Set<number>; lead: number; title: string; body: string }>()
  for (const { key } of blobs) {
    const d = (await s.get(key, { type: "json" })) as any
    for (const e of d?.schedule || []) {
      const [id, occStr, leadStr] = String(e.k).split(":")
      const occ = Number(occStr), lead = Number(leadStr) || 0
      if (!id || !Number.isFinite(occ)) continue
      let r = byId.get(id)
      if (!r) byId.set(id, (r = { id, occ: new Set(), lead: 0, title: String(e.title), body: "" }))
      if (lead) r.lead = Math.max(r.lead, lead)
      else { r.occ.add(occ); r.body = String(e.body || "") }
    }
  }
  return [...byId.values()].filter((r) => r.occ.size).map((r) => {
    const occ = [...r.occ].sort((a, b) => a - b)
    const sp = r.title.indexOf(" ")
    const emoji = sp > 0 ? r.title.slice(0, sp) : "✨"
    const title = sp > 0 ? r.title.slice(sp + 1) : r.title
    const nl = r.body.indexOf("\n")
    let repeat: string | null = null
    if (occ.length > 1) {
      const days = (occ[1] - occ[0]) / 864e5
      repeat = days < 1.5 ? "daily" : days < 8 ? "weekly" : days < 40 ? "monthly" : "yearly"
    } else if (/\b(birthday|bday|b-day|anniversary)\b/i.test(title)) repeat = "yearly"
    return {
      id: r.id, title, emoji, when: new Date(occ[0]).toISOString(),
      allDay: r.body.startsWith("Happening today"), repeat, lead: r.lead,
      notes: nl >= 0 ? r.body.slice(nl + 1) : "", done: false, created: Date.now(),
    }
  })
}

// ---------- function ----------

export default async (req: Request, context: Context) => {
  const path = new URL(req.url).pathname
  try {
    if (path === "/api/vapid") {
      const { publicKey } = await getVapid()
      return Response.json({ publicKey })
    }

    const body: any = await req.json().catch(() => null)

    if (path === "/api/vault") {
      const pinCheck = await checkPin(body?.pin)
      if (pinCheck !== "ok") return Response.json({ error: pinCheck === "locked" ? "locked" : "wrong-pin" }, { status: pinCheck === "locked" ? 429 : 403 })
      if (body.action === "save") {
        if (!Array.isArray(body.items)) return Response.json({ error: "Missing items" }, { status: 400 })
        if (JSON.stringify(body.items).length > 2_000_000) return Response.json({ error: "Too big" }, { status: 413 })
        const updated = Number(body.updated) || Date.now()
        await store().setJSON("vault", { items: body.items, updated })
        return Response.json({ ok: true, updated })
      }
      const vault = await store().get("vault", { type: "json" })
      const recovered = body.action === "recover" ? await recoverFromSchedules() : []
      return Response.json({ ok: true, vault, recovered })
    }

    const sub = cleanSubscription(body?.subscription)
    if (!sub) return Response.json({ error: "Missing or invalid push subscription" }, { status: 400 })
    const key = deviceKey(sub.endpoint)

    if (path === "/api/sync") {
      if (req.method === "DELETE") {
        await store().delete(key)
        return Response.json({ ok: true })
      }
      const schedule = cleanSchedule(body.schedule)
      await store().setJSON(key, { sub, schedule, updated: Date.now() })
      return Response.json({ ok: true, scheduled: schedule.length })
    }

    if (path === "/api/test") {
      const status = await sendPush(
        sub,
        { title: "🔔 Nudge is working", body: "This is what a reminder will look like.", tag: "nudge-test" },
        await getVapid(),
        subjectFor(context.site?.url),
      )
      return Response.json({ ok: status < 300, status }, { status: status < 300 ? 200 : 502 })
    }

    return new Response("Not found", { status: 404 })
  } catch (err) {
    console.error(err)
    return Response.json({ error: "Something went wrong" }, { status: 500 })
  }
}

export const config: Config = {
  path: ["/api/vapid", "/api/sync", "/api/test", "/api/vault"],
  method: ["GET", "POST", "DELETE"],
}
