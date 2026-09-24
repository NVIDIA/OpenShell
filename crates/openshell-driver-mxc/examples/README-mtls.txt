OpenShell CLI <-> gateway mTLS test (T2)
========================================

WHAT THIS PROVES
  T2 is the CONTROL CHANNEL, not inference. It verifies that the gateway's
  management API (sandbox create/list/etc.) is served over mutual TLS and that a
  client presenting NO certificate is rejected at the TLS handshake. It does not
  touch the MXC sandbox or any inference endpoint, and needs no API key.

  PASS requires all of:
    - gateway logs: TLS enabled + client cert verification + mTLS user auth
    - CLI `gateway add` and `sandbox list` succeed over https (real mTLS RPCs)
    - a no-cert curl client is refused (curl exit 56 + gateway logs the rejection)

PREREQUISITES
  - Drop run-mtls-test.ps1 into the SAME folder that already has:
      openshell-gateway.exe
      openshell.exe
    (the existing openshell-inference-test folder works as-is)
  - No API key, no wxc-exec, no network egress required. Pure loopback.

RUN
  powershell -NoProfile -ExecutionPolicy Bypass -File .\run-mtls-test.ps1

  Optional:
    -TlsDir C:\work\openshell-mtls   (where throwaway certs are generated)
    -Port 17670                      (gateway bind port)
    -KeepRunning                     (leave the gateway up for inspection)

OUTPUT
  results-mtls-<timestamp>.zip in the same folder. Hand that back.
  The bundle contains: gateway.log, transcript.txt, summary.txt, and the PUBLIC
  server cert. Throwaway PRIVATE keys are intentionally NOT included.

NOTE
  A gateway named "openshell" may already be registered from a prior run; the
  script removes/re-adds it automatically. The decisive proof is the
  `sandbox list` RPC succeeding over mTLS plus the no-cert client being refused.
