# Clean-room tester flow

Self-hosted n8n only; use Node 20+ and npm for the local CLI steps.

1. In n8n, **Settings > Community Nodes > Install** `n8n-nodes-besa`.
2. In a fresh local directory, install the public CLI and its example manifest:

   ```bash
   mkdir besa-n8n-demo
   cd besa-n8n-demo
   npm init -y
   npm install @dorigjo/besa@1.3.0
   node -e "const fs=require('node:fs');fs.mkdirSync('examples',{recursive:true});fs.copyFileSync('node_modules/@dorigjo/besa/examples/manifest.yaml','examples/manifest.yaml');"
   ```

3. Set a fresh private passphrase of at least 16 UTF-8 bytes. Choose your shell:

   ```bash
   export BESA_KEY_PASSPHRASE='REPLACE_WITH_A_FRESH_PRIVATE_PASSPHRASE'
   ```

   ```powershell
   $env:BESA_KEY_PASSPHRASE = 'REPLACE_WITH_A_FRESH_PRIVATE_PASSPHRASE'
   ```

   The CLI does not prompt interactively. Alternatively, add
   `--passphrase-file /secure/path/passphrase.txt` to both commands below.
4. Run `npx besa keys`. It creates/loads the encrypted local `.besa/key.json`.
5. Run `npx besa sign examples/manifest.yaml`. It writes `examples/manifest.signed.json`.
6. Download [examples/workflows/besa-demo.workflow.json](examples/workflows/besa-demo.workflow.json) and import it via **Workflows > Import from File**.
7. In **Besa: Create Receipt**, create/select a **Besa Signing Key API** credential. Paste the **full encrypted `.besa/key.json` contents** into **Stored Key Pair**, not a raw private key.
8. Enter the **same passphrase** in the credential and save it. The imported credential ID is only a placeholder.
9. In **Set Signed Manifest**, leave `signedManifest` as type **Object**, switch its value to **Fixed**, and replace the placeholder with the **full `examples/manifest.signed.json` contents**. Leave `demoRequest` unchanged: it already matches `crm.lookup`.
10. Execute the workflow. Expected: **Verify Signed Manifest** succeeds; **Check Admission** returns **allow / ALLOWED** for `crm.lookup`; **Create Receipt** succeeds; **Verify Receipt** returns **valid / OK**.

The minimal demo calls no real API. The optional IF/HTTP extension is in the [README](README.md#optional-real-tool-call-extension).

Never commit `.besa/` or paste keys/passphrases into [GitHub issues](https://github.com/dorigjo/besa/issues). Use a fresh private passphrase and appropriate key management in production. Report only the failing operation and a sanitized error message.
