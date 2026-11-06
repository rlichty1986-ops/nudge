# Nudge

A calm, calendar-free important-dates app. No login. Voice or typing. Themes. Push reminders.

## Put it online (5 minutes, free)

Nudge has a small background helper that sends notifications when the app is closed, so it needs
Netlify to **build** it. Plain drag-and-drop (Netlify Drop) only publishes static files and would
skip the helper. Pick one of these:

### Option A: GitHub (easiest to update later)
1. Create a new repository on github.com and upload everything in this folder (keep the folder structure).
2. In Netlify: **Add new project → Import an existing project → GitHub**, then pick the repo.
3. Leave the settings as they are (they're read from `netlify.toml`) and click **Deploy**.

### Option B: Netlify CLI
```
npm install -g netlify-cli
cd nudge
netlify deploy --build --prod
```

There's nothing to configure: no API keys and no environment variables. The notification keys are
created automatically the first time someone turns reminders on.

## Turning on reminders

- **Android / computer (Chrome, Edge, Firefox):** tap the 🔕 bell, then allow notifications.
- **iPhone / iPad:** in Safari tap **Share → Add to Home Screen**, open Nudge from the Home Screen, then tap the bell. (Apple only allows notifications for Home Screen web apps, iOS 16.4+.)

Each device turns on reminders separately. Tap the 🔔 bell again any time to send a test or turn reminders off.

**When reminders fire:** at the item's time; all-day items fire at 9:00 AM. Tap an item and pick
**Heads-up** to also get a ping 10 minutes, 1 hour or 1 day before.

## How it works

| Piece | File |
|---|---|
| The app (everything you see) | `public/index.html` |
| Shows notifications, works offline | `public/sw.js` |
| Saves this device's upcoming reminder times | `netlify/functions/api.mts` |
| Checks every minute and sends what's due | `netlify/functions/send-reminders.mts` |
| Push encryption (no outside services) | `netlify/lib/webpush.mts` |

Your reminders live on your device. When reminders are on, the titles and times for the next 90 days
are also copied to your own Netlify project's storage (Netlify Blobs) so they can be sent while the app
is closed. Turning reminders off deletes that copy.

Voice input uses the browser's speech recognition: Chrome, Edge and Safari support it, Firefox doesn't.
