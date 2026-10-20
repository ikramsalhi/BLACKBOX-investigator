# BLACKBOX v1.9: Enable login on Railway

1. Open the **Railway project** containing `blackbox-investigator-production` and locate the application's **persistent volume**. Your private cases, raw captures, account hashes and sessions are under `/var/lib/blackbox` in this Docker image. **If a volume is not attached yet, back up any existing case data first**—mounting a new empty volume might hide older container data.
2. Deploy this source to `https://github.com/ikramsalhi/BLACKBOX-investigator` using `PUSH_AUTH_UPDATE_WINDOWS.bat` or GitHub Desktop. Wait for Railway to build it.
3. In the Railway application's **Variables** section, enter the following values as private variables (not in GitHub):

   | Variable | Value |
   |---|---|
   | `BLACKBOX_DEPLOY_MODE` | `hybrid` |
   | `BLACKBOX_PUBLIC_HOST` | `blackbox-investigator-production.up.railway.app` (no `https://`) |
   | `BLACKBOX_BOOTSTRAP_USER` | Choose an account username (3–48 characters: letters/numbers/._-) |
   | `BLACKBOX_BOOTSTRAP_PASSWORD` | Choose a long, unique password of at least 16 characters |
   | `BLACKBOX_SIGNUP_INVITE_CODE` | Optional long secret (20+ characters) for invited signups; omit to disable self-registration |

4. Redeploy / restart using Railway's UI. Confirm that visiting the project URL as a logged-out visitor still shows the **public synthetic demo**, with a **Sign in / Register** button. Sign in with the bootstrap credentials. Create a **private investigation**, upload an authorized test PCAP, and download the report. Open an incognito window to confirm the new private case is **not** visible to visitors.
5. Use **Sign out** to invalidate the session. Session cookies are Secure, HttpOnly, SameSite=Strict and expire after 12 hours. An untrusted origin, missing CSRF token, or another user's case is rejected by the API. Accounts have case and capture quotas.

**Security notes:** Do not put your Railway password, invite code, or cloud AI keys in GitHub. This is an early-stage pilot and has not undergone an independent security audit; use synthetic or authorized, nonsensitive evidence until deployment hardening and backups are verified. No email-based identity verification or password-reset flow exists yet. More robust rate limiting/shared auth storage will be needed if you scale past one Railway application instance. **For Thirduni judges, leave the public synthetic gallery accessible; do not put the whole site behind a login.**
