# Transparent TCP Redis

This example connects a Docker-backed Ryno sandbox to Redis with a native
TCP client. It does not use the HTTP forward proxy.

The demo:

1. Starts Redis on the Ryno-managed Docker network.
2. Creates a sandbox with an endpoint that explicitly uses `protocol: tcp`.
3. Resolves the policy hostname to an ephemeral synthetic address.
4. Opens a native TCP socket and runs Redis `PING`, `SET`, `GET`, and `DEL` commands.
5. Confirms that policy blocks an unapproved hostname, the approved hostname
   on the wrong port, and a direct connection to Redis's real IP.
6. Prints the sandbox log stream, including OCSF DNS and TCP decisions.
7. Deletes the sandbox and Redis container, including after a failure.

Ryno authorizes the hostname and port before policy DNS publishes the
synthetic address. When the client connects, Ryno maps that address back
to the approved endpoint, rechecks the process and policy, and dials a pinned
real Redis address. A direct connection to the Redis container IP remains
blocked.

## Prerequisites

- A Docker-backed Ryno gateway built from the transparent TCP branch
- The `ryno` and `docker` commands
- Access to pull `redis:7-alpine`

The Docker compute driver creates and uses the `ryno-docker` bridge by
default. The gateway process itself runs on the host; only sandbox supervisors
and the Redis service join this bridge. If the driver uses another network, set
`RYNO_DOCKER_NETWORK` to that network's name.

## Run the example

From the repository root:

```shell
examples/transparent-tcp-redis/demo.sh
```

Expected client output includes:

```text
policy DNS: redis.ryno.demo -> 198.18.x.x
PING -> 'PONG'
SET -> 'OK'
GET -> 'hello-from-ryno'
DEL -> 1
BLOCKED (unapproved hostname): ryno-transparent-tcp-redis-demo:6379 -> gaierror
BLOCKED (wrong port): redis.ryno.demo:6380 -> RuntimeError
BLOCKED (direct real-IP dial): 172.x.x.x:6379 -> ConnectionRefusedError
transparent TCP Redis demo passed
```

The exact exception names vary by operating system and network timing. The
demo fails if any negative check receives a Redis response.

Before cleanup, the demo fetches recent sandbox logs and prints only the OCSF
events relevant to this flow: policy DNS mappings and denials, transparent TCP
allows and wrong-port denials, and direct-bypass findings when the runtime can
observe them.

The synthetic address changes across supervisor allocation epochs. It is not
the Redis container's address and applications must not persist it.

The demo currently requires the Docker compute driver. Other compute drivers
fail closed when a policy requests `protocol: tcp` until they implement the
required namespace-local DNS and TCP capture contract.

Create the sandbox with at least one explicit TCP endpoint. Adding the first
`protocol: tcp` endpoint to a running sandbox that started without one is
rejected atomically, with the previous policy left active; recreate the sandbox
to install the DNS and transparent TCP substrate before the workload starts.

The example policy allows any sandbox binary to use this one Redis endpoint so
the demo works across base images with different Python installation paths. In
a production policy, replace `/**` with the exact path of the client binary.

## Configuration

Override resource names or the image without editing the files:

```shell
SANDBOX_NAME=tcp-redis-demo \
REDIS_CONTAINER=my-ryno-redis \
REDIS_IMAGE=redis:7-alpine \
RYNO_DOCKER_NETWORK=ryno-docker \
examples/transparent-tcp-redis/demo.sh
```
