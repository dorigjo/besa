# Tester flow

1. **Install this**: in your self-hosted n8n, Settings > Community Nodes > Install `n8n-nodes-besa`.
2. **Import this workflow**: `examples/workflows/besa-demo.workflow.json` (Workflows > Import from File).
3. **Run it**: you'll need a signed manifest and key (`npm install -g @dorigjo/besa && besa keygen && besa sign examples/manifest.yaml`) -- paste the signed manifest into the `Set Signed Manifest` node and the key/passphrase into the `Besa Signing Key` credential, then execute the workflow.
4. **Tell me where it breaks**: open an issue at https://github.com/dorigjo/besa/issues with the node/operation that failed and the error message (never paste your passphrase or key file contents).
