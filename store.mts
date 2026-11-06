import crypto from "node:crypto"
import { getStore } from "@netlify/blobs"
import { generateVapid, type Vapid, type PushSubscriptionJSON } from "./webpush.mts"

export type ScheduleEntry = { k: string; at: number; title: string; body: string }
export type Device = { sub: PushSubscriptionJSON; schedule: ScheduleEntry[]; updated: number }

export const store = () => getStore({ name: "nudge", consistency: "strong" })

export const deviceKey = (endpoint: string) =>
  "devices/" + crypto.createHash("sha256").update(endpoint).digest("hex").slice(0, 40)

// VAPID keys are created automatically on first use and kept in Blobs, so there is nothing to configure.
export async function getVapid(): Promise<Vapid> {
  const s = store()
  const existing = (await s.get("vapid", { type: "json" })) as Vapid | null
  if (existing) return existing
  const fresh = generateVapid()
  const { modified } = await s.setJSON("vapid", fresh, { onlyIfNew: true })
  return modified ? fresh : ((await s.get("vapid", { type: "json" })) as Vapid)
}

export function subjectFor(siteUrl?: string): string {
  const url = siteUrl || Netlify.env.get("URL")
  return url && url.startsWith("https://") ? url : "mailto:nudge-app@users.noreply.github.com"
}

export function cleanSubscription(raw: any): PushSubscriptionJSON | null {
  if (!raw || typeof raw.endpoint !== "string" || !raw.endpoint.startsWith("https://")) return null
  const { p256dh, auth } = raw.keys || {}
  if (typeof p256dh !== "string" || typeof auth !== "string") return null
  return { endpoint: raw.endpoint.slice(0, 1000), keys: { p256dh: p256dh.slice(0, 200), auth: auth.slice(0, 100) } }
}

export function cleanSchedule(raw: any): ScheduleEntry[] {
  if (!Array.isArray(raw)) return []
  const now = Date.now()
  return raw
    .filter((x) => x && Number.isFinite(x.at) && x.at > now - 60_000 && x.at < now + 400 * 864e5)
    .slice(0, 400)
    .map((x) => ({ k: String(x.k ?? "").slice(0, 120), at: Number(x.at), title: String(x.title ?? "Nudge").slice(0, 140), body: String(x.body ?? "").slice(0, 240) }))
}
