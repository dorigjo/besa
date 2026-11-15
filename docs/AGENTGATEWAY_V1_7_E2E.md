# Agentgateway v1.7 E2E

This local reference test places the BESA executor in the MCP application
behind the real, digest-pinned agentgateway v1.7.0 container. It uses a mock
refund handler and ephemeral test keys; it never contacts a payment processor.

## Run

Requirements: Docker with the pinned image available and Node.js 20 or later.

```sh
npm ci
docker pull cr.agentgateway.dev/agentgateway@sha256:60216aafb03d37f94e952ff3d51d2f630a65b10ecaebdc0a864882f92610c45b
npm run test:e2e:agentgateway
```

The runner uses `--pull=never` after the explicit image pull. It binds the
gateway listener to loopback; the mock backend listens on the host interface so
Docker Desktop can reach it. Run only on a trusted development machine: the
short-lived test API key and backend capability are embedded in the temporary
gateway configuration and are not suitable for production.

## What the test proves

The test uses the pinned container and an MCP Streamable HTTP client. It checks
that unauthenticated traffic is rejected before backend forwarding, a direct
backend call with spoofed identity headers is rejected, and a valid gateway
key alone cannot authorize a tool invocation. A missing admission and changed
refund amount are denied with zero protected-handler calls. The matching
admission reaches the protected handler once; replay is rejected without a
second call. The harness sends a bounded evidence bundle containing no signing
keys to a fresh Node.js verifier process. That process verifies the admission
and execution evidence using public trust material, then rejects modified
action parameters and a modified result.

Agentgateway is responsible for its configured request authentication and
routing. The application must establish trusted caller identity, map the
actual MCP tool and arguments into the BESA request, and keep every sensitive
execution path behind the protected handler. Native gateway policies can also
enforce tool and argument restrictions; this example does not claim that
BESA's allow/deny enforcement is unique. BESA's additional output is a
signed, exact-request-bound admission/evidence contract that can be retained
and verified without trusting gateway logs.

## Limits

- This is a local container and mock-handler test, not an external integration,
  production identity-provider test, or payment execution.
- The configured test identity is gateway key metadata. A production adapter
  must derive identity from a verified JWT, mTLS/workload identity, or another
  authenticated and integrity-protected source; arbitrary request headers are
  not trusted identity.
- Replay in this harness is in-memory and process-local. Multi-process or
  multi-host deployment requires an atomic shared replay store.
- A direct network path to an unwrapped backend remains a deployment bypass.
  Restrict backend reachability and route every consequential implementation
  through the wrapper.
- Signed execution evidence authenticates the recorder's supplied result; it
  does not independently prove that an external system performed the action.
- The unauthenticated denial body may be plain text rather than MCP JSON-RPC;
  some local network stacks also reject the response as malformed HTTP. The
  runner accepts only an observed HTTP 401/403 or that specific transport
  rejection, and verifies zero backend forwarding and zero handler calls. It
  does not claim a valid JSON-RPC denial body.

Agentgateway documents MCP authorization by tool name/target and notes that
MCP arguments are not available to `mcpAuthorization` rules; route-level HTTP
authorization can inspect `mcp.tool.arguments`. See the [MCP authorization
documentation](https://agentgateway.dev/docs/standalone/latest/documentation/configuration/security/mcp-authz/)
and [agentgateway v1.7.0 release](https://github.com/agentgateway/agentgateway/releases/tag/v1.7.0).
