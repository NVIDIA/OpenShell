# Networking review checklist

Each rule comes from a networking defect that shipped in OpenShell and was
fixed later. Check every rule that applies to the diff, on every protocol
branch and runtime the change touches. A violation that the diff introduces or
worsens is a finding; cite the rule in the invariant.

## Policy enforcement and L7

1. An L7-inspected route fails closed. No branch falls back to a raw tunnel,
   and `Upgrade`/`101` responses are refused unless the upgraded protocol is
   also inspected.
2. Canonicalize host and path once, before policy evaluation, and dial exactly
   what policy authorized. Dot segments, `;params`, repeated slashes, percent
   encodings, and IPv4-mapped addresses cannot change meaning after the check.
3. One matcher per concern. When Rust route selection and Rego authorization
   both evaluate a selector, they use the same glob, case, and normalization
   semantics.
4. Per-request decisions on a keep-alive connection do not depend on earlier
   requests on the same connection. Forward exactly one message's framing per
   decision.
5. Body framing (`Content-Length`, chunked) decides where a message ends;
   `Connection: close` decides only reuse. Chunk boundaries survive relay.
6. Address pins and DNS results are scoped to the endpoint that authorized
   them and re-validated on change. A literal IP or wildcard host never grants
   a private or always-blocked address implicitly.
7. Blocklist checks cover the whole CIDR range, not just its network address,
   and treat IPv4-mapped IPv6 as IPv4. Host-gateway and alias addresses are
   checked against the SSRF ranges; an exemption names only the exact trusted
   address.
8. Destination resolution never trusts workload-controlled files such as
   the sandbox's `/etc/hosts` or `resolv.conf`.
9. Auto-approval re-checks every destination field (`host`, ports,
   `allowed_ips`, CIDRs) against the currently stored rule.

## Connection lifecycle and flow control

10. Buffers are bounded and backpressure propagates end to end. A slow reader
    stalls its writer instead of growing a queue or parse buffer.
11. HTTP/2 connection windows are at least the sum of the stream windows that
    can be open at once.
12. Accept loops distinguish transient errors (`EMFILE`, `ECONNABORTED`) from
    terminal ones and keep serving after transient errors.
13. Reconnect backoff resets after a successful session and stops on
    non-retryable errors such as authentication failure.
14. Long-lived sessions have keepalives, bounded waits, and a draining
    shutdown that releases every resource.
15. Half-close is preserved: EOF in one direction does not abort the other
    direction of a relay.
16. Timeouts on pooled or long-lived clients are per request. A connection
    read timeout must not count idle time or kill watches and streams.
17. Readiness and success are proven by probing or by the peer's response,
    never by a timer.
18. Limits come from live usage and OS limits (`RLIMIT_NOFILE`), not from a
    startup snapshot.
19. Latency-sensitive TCP hops set `TCP_NODELAY` through
    `openshell_core::net` helpers, including accepted sockets.

## Transport, TLS, and trust

20. Clients that carry secrets or fetch trust roots (Vault, OIDC discovery,
    JWKS, registries) require HTTPS except numeric loopback, refuse redirects,
    and pin the expected origin. They do not rely on default HTTP client
    settings.
21. A private CA is trusted only by the client that needs it, never
    process-wide through `SSL_CERT_FILE` or the global store.
22. An endpoint rewrite keeps scheme, host, and port from one source, and
    never moves an `https` endpoint to a host outside the certificate's SANs.
    Certificates are reissued when required SANs change.
23. Protocol-upgrade routes on a shared listener (`/_ws_tunnel`, WebSocket)
    are opt-in or authenticated and check `Origin`. Control-plane listeners
    default to a Unix socket with peer verification, not unauthenticated TCP.
24. A rewrite of a transport ports its trust stores, endpoints, and
    authentication along with it.

## Addressing and runtimes

25. Host and port strings come from one helper that brackets IPv6 literals.
    Use `Url::port_or_known_default()`, not `Url::port()`.
26. Gateway callback routing works on every runtime: Linux, rootless
    (pasta), and Docker or Podman inside a VM (Docker Desktop, Colima,
    OrbStack, Podman machine). Do not rely on bridge IPs or `host-gateway`
    alone.
27. Sandbox containers never share the host network namespace.
28. Unix socket paths fit `sun_path` (104 bytes on macOS).
29. Values from a server or policy are validated and shell-escaped before
    reaching an SSH `ProxyCommand` or other command line.
30. Client SSH sessions disable connection sharing (`ControlMaster`,
    `ControlPath`) on every path that addresses a sandbox, not only one.
31. Helm in-cluster URLs, SANs, and object references derive from the release
    name and namespace, and use the same expressions as the objects they
    reference.

## Socket broker and process networking

32. Broker limits derive from OS limits; transient errors (`ENOENT`, `EINTR`)
    are retried; state that cannot be verified fails closed.
33. Descriptors are reclaimed before exhaustion, and every mediated socket is
    closed on every exit path.
