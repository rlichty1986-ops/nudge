// Runs every minute: sends a push for every reminder that has come due on any registered device.
import type { Config, Context } from "@netlify/functions"
import { sendPush } from "../lib/webpush.mts"
import { store, getVapid, subjectFor, type Device } from "../lib/store.mts"

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
