# OpenClaw Sandbox

## Quick start

```sh
nemoclaw sandbox create --forward 18789 -- openclaw-start
```

`openclaw-start` is a helper script pre-installed in the sandbox that runs the
onboarding wizard, starts the gateway as a background daemon, and prints the
access URL.

The CLI returns automatically once the script finishes; the port
forward continues running in the background.

Once the command completes, the gateway is accessible locally:

- **Control UI:** http://127.0.0.1:18789/
- **Health check:** `openclaw health`

Note: you will need use the auth token present in the bootstrapping process to connect to the endpoint.

## Step-by-step alternative

### Create the sandbox

```sh
nemoclaw sandbox create --keep --forward 18789
```

Inside the sandbox, run the onboarding wizard and start the gateway:

```sh
openclaw onboard
nohup openclaw gateway run > /tmp/gateway.log 2>&1 &
exit
```
