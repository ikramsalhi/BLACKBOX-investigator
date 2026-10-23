# BLACKBOX — one-click Windows launcher

Double-click **start_windows.bat** in the project root. A terminal starts the localhost server and opens your web browser. Keep the terminal open while using BLACKBOX.

On the welcome screen, choose **Private investigator** to create the first local account (password at least 16 characters) or sign in, or **Explore the demo** to view read-only synthetic captures. Subsequent users need an invitation code configured by the owner.

To test locally, open http://127.0.0.1:8765/api/health and check `mode: local-hybrid`. Don't expose the localhost server to the network.

Railway continues to use `BLACKBOX_DEPLOY_MODE=hybrid` (HTTPS). The deployment's secrets and existing captured evidence are not part of this repository.

Old local cases are preserved on disk, but anonymous cases are not automatically owned by the first new account.
