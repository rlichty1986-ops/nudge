// Endpoints the app calls:
//   GET    /api/vapid  -> public key the browser needs to subscribe
//   POST   /api/sync   -> save this device's subscription + upcoming reminder times
//   DELETE /api/sync   -> forget this device
//   POST   /api/test   -> send a test notification right now
import type { Config, Context } from "@netlify/functions"
import { sendPush } from "../lib/webpush.mts"
import { store, deviceKey, getVapid, subjectFor, cleanSubscription, cleanSchedule } from "../lib/store.mts"

export default async (req: Request, context: Context) => {
  const path = new URL(req.url).pathname
  try {
    if (path === "/api/vapid") {
      const { publicKey } = await getVapid()
      return Response.json({ publicKey })
    }

    const body: any = await req.json().catch(() => null)
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
  path: ["/api/vapid", "/api/sync", "/api/test"],
  method: ["GET", "POST", "DELETE"],
}
