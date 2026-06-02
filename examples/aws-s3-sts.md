# Manual E2E Test: S3 Access via STS Credentials

This guide walks through an end-to-end test of an OpenShell sandbox accessing
AWS S3 using gateway-minted STS temporary credentials with proxy-side SigV4
re-signing. The sandbox never sees real AWS credentials — the proxy resolves
placeholders and signs requests on the fly.

## Prerequisites

- AWS CLI authenticated (`aws sts get-caller-identity` succeeds)
- Podman running (`podman info` succeeds)
- OpenShell built from source with AWS STS refresh and SigV4 signing support

## 1. Create AWS test resources

Create an S3 bucket and an IAM role the gateway can assume:

```shell
BUCKET="openshell-sts-test-$(date +%s)"
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)

aws s3 mb "s3://${BUCKET}" --region us-east-1

aws iam create-role \
  --role-name openshell-sts-test-role \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::'${ACCOUNT}':root"},
      "Action": "sts:AssumeRole"
    }]
  }'

aws iam put-role-policy \
  --role-name openshell-sts-test-role \
  --policy-name s3-access \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": ["s3:PutObject", "s3:GetObject", "s3:ListBucket"],
      "Resource": ["arn:aws:s3:::'${BUCKET}'", "arn:aws:s3:::'${BUCKET}'/*"]
    }]
  }'
```

Verify the role works:

```shell
aws sts assume-role \
  --role-arn "arn:aws:iam::${ACCOUNT}:role/openshell-sts-test-role" \
  --role-session-name test \
  --query Credentials.AccessKeyId --output text
```

## 2. Build the supervisor image

The supervisor image must include the SigV4 re-signing code and the updated
proto definitions. Build it from the branch:

```shell
CONTAINER_ENGINE=podman IMAGE_TAG=dev mise run build:docker:supervisor
```

Verify the image exists locally:

```shell
podman images | grep "openshell/supervisor.*dev"
```

## 3. Start the gateway

The gateway needs AWS credentials in its environment to call `sts:AssumeRole`.
Export them before starting:

```shell
eval "$(aws configure export-credentials --format env)"
```

The gateway must use the locally built supervisor image. The `mise run gateway`
script places `supervisor_image` in the wrong TOML section, so start the gateway
binary directly with a hand-written config.

Write `.cache/gateway-podman/gateway.toml` in the repo root (adjust JWT paths
if your gateway cache directory differs):

```toml
[openshell]
version = 1

[openshell.gateway]
compute_drivers = ["podman"]
default_image = "ghcr.io/nvidia/openshell-community/sandboxes/base:latest"
disable_tls = true
supervisor_image = "localhost/openshell/supervisor:dev"

[openshell.gateway.auth]
allow_unauthenticated_users = true

[openshell.gateway.gateway_jwt]
signing_key_path = ".cache/gateway-podman/tls/jwt/signing.pem"
public_key_path = ".cache/gateway-podman/tls/jwt/public.pem"
kid_path = ".cache/gateway-podman/tls/jwt/kid"
gateway_id = "podman-dev"
ttl_secs = 3600

[openshell.drivers.podman]
image_pull_policy = "missing"
```

If the JWT key files do not exist yet, run `mise run gateway` once to generate
them, then stop the gateway and restart with the config above.

Start the gateway:

```shell
eval "$(aws configure export-credentials --format env)"
./target/debug/openshell-gateway \
  --config .cache/gateway-podman/gateway.toml \
  --port 18080 --log-level info --drivers podman --disable-tls \
  --db-url "sqlite:.cache/gateway-podman/gateway.db?mode=rwc"
```

## 4. Configure the provider

In a separate terminal:

```shell
export OPENSHELL_BASE_URL=http://localhost:18080

# Enable provider v2 (required for STS)
openshell settings set --global --key providers_v2_enabled --value true --yes

# Create the provider with the aws-s3 profile
openshell provider create --name s3-test --type aws-s3 \
  --credential AWS_ACCESS_KEY_ID=placeholder

# Configure STS refresh
openshell provider refresh configure s3-test \
  --credential-key AWS_ACCESS_KEY_ID \
  --strategy aws-sts-assume-role \
  --material role_arn="arn:aws:iam::${ACCOUNT}:role/openshell-sts-test-role" \
  --material session_name="openshell-sandbox" \
  --material aws_region="us-east-1"

# Mint the first set of credentials
openshell provider refresh rotate s3-test \
  --credential-key AWS_ACCESS_KEY_ID

# Verify
openshell provider refresh status s3-test
```

The status should show `refreshed` with an expiry ~1 hour from now.

## 5. Test S3 access from a sandbox

### Using boto3 (Python)

```shell
openshell sandbox create --name s3-smoke \
  --provider s3-test \
  -- bash -c '
export AWS_CA_BUNDLE=/etc/openshell-tls/ca-bundle.pem
pip install boto3 -q 2>&1 | tail -1
python3 -c "
import boto3

s3 = boto3.client(\"s3\", region_name=\"us-east-1\")

print(\"Upload...\")
s3.put_object(
    Bucket=\"'"${BUCKET}"'\",
    Key=\"from-sandbox.txt\",
    Body=b\"hello from openshell sandbox via STS\"
)
print(\"OK\")

print(\"List...\")
resp = s3.list_objects_v2(Bucket=\"'"${BUCKET}"'\", MaxKeys=5)
for obj in resp.get(\"Contents\", []):
    print(\"  \" + obj[\"Key\"] + \" (\" + str(obj[\"Size\"]) + \" bytes)\")

print(\"Download...\")
body = s3.get_object(
    Bucket=\"'"${BUCKET}"'\",
    Key=\"from-sandbox.txt\"
)[\"Body\"].read()
print(body.decode())
"
'
```

All three operations should succeed. The download should print
`hello from openshell sandbox via STS`.

### Using curl

```shell
openshell sandbox create --name s3-curl \
  --provider s3-test \
  -- bash -c '
BUCKET="'"${BUCKET}"'"
REGION="us-east-1"
CA=/etc/openshell-tls/ca-bundle.pem

echo "=== Upload ==="
curl -s --cacert $CA -X PUT -H "Content-Type: text/plain" \
  -d "hello from openshell sandbox via STS" \
  "https://${BUCKET}.s3.${REGION}.amazonaws.com/from-sandbox.txt" \
  -w "HTTP %{http_code}\n"

echo ""
echo "=== Download ==="
curl -s --cacert $CA \
  "https://${BUCKET}.s3.${REGION}.amazonaws.com/from-sandbox.txt" \
  -w "\nHTTP %{http_code}\n"
'
```

Both operations should return `HTTP 200`.

### What's happening

1. The gateway called `sts:AssumeRole` and stored three short-lived credentials
   (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`) in the
   provider record.
2. The sandbox received placeholder values for these credentials as environment
   variables.
3. The client (boto3 or curl) sent an HTTP request through the sandbox proxy's
   CONNECT tunnel. boto3 signs the request with placeholder credentials; curl
   sends unsigned requests. Either way, the proxy handles it.
4. The proxy terminated TLS, stripped any existing AWS auth headers, resolved
   the real credentials from the `SecretResolver`, computed a fresh SigV4
   signature using the `aws-sigv4` crate, and forwarded the signed request to
   S3.
5. S3 validated the signature and accepted the request.

The sandbox never saw real AWS credentials — only placeholders.

### TLS CA trust

The proxy terminates TLS and presents a certificate signed by the OpenShell
Sandbox CA. Curl needs `--cacert /etc/openshell-tls/ca-bundle.pem` to trust
it. Python clients need `AWS_CA_BUNDLE=/etc/openshell-tls/ca-bundle.pem` set
in the environment.

## 6. Clean up

```shell
# Delete the sandbox
openshell sandbox delete s3-smoke

# Delete AWS resources
aws s3 rb "s3://${BUCKET}" --force
aws iam delete-role-policy --role-name openshell-sts-test-role --policy-name s3-access
aws iam delete-role --role-name openshell-sts-test-role
```

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `STS AssumeRole failed: dispatch failure` | Gateway doesn't have AWS credentials | Export credentials before starting: `eval "$(aws configure export-credentials --format env)"` |
| `Policy discovery sync failed: invalid wire type` | Supervisor image doesn't have updated proto | Rebuild: `CONTAINER_ENGINE=podman IMAGE_TAG=dev mise run build:docker:supervisor` |
| `CONNECT ... not permitted by policy` | Binary not in profile's `binaries` list | Use curl (in the list) or add your binary path to the policy |
| `403 AccessDenied` from S3 | IAM role missing permissions, or STS creds expired | Check `openshell provider refresh status`; re-rotate if expired |
| Supervisor uses wrong image | `mise run gateway` places `supervisor_image` in wrong TOML section | Use the hand-written config from step 3 instead of `mise run gateway` |
