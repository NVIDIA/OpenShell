# Open VSCode in a Sandbox

Connect VSCode to a running sandbox using the
[Remote - SSH](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-ssh)
extension so you get a full IDE experience inside the sandbox environment.

## Prerequisites

- A running nemoclaw gateway (`nemoclaw gateway start`)
- [VSCode](https://code.visualstudio.com/) with the
  [Remote - SSH](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-ssh)
  extension installed
- The `nemoclaw` CLI on your `PATH`

## Quick start

### 1. Create a sandbox

```bash
nemoclaw sandbox create --keep --name my-sandbox
```

`--keep` prevents the sandbox from being cleaned up when the shell exits so
VSCode can reconnect to it later.

### 2. Generate an SSH config entry

```bash
nemoclaw sandbox ssh-config my-sandbox >> ~/.ssh/config
```

This will append a block like:

```text
Host nemoclaw-my-sandbox
    User sandbox
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
    GlobalKnownHostsFile /dev/null
    LogLevel ERROR
    ProxyCommand nemoclaw ssh-proxy --cluster <cluster-name> --name my-sandbox
```

### 3. Open VSCode

Open VSCode and run **Remote-SSH: Connect to Host...** from the command
palette (`Cmd+Shift+P` / `Ctrl+Shift+P`). Select `nemoclaw-my-sandbox` from the
list. VSCode will open a remote window connected to the sandbox.

Alternatively, from the terminal:

```bash
code --remote ssh-remote+nemoclaw-my-sandbox /sandbox
```

### 4. Clean up

When you are done, delete the sandbox:

```bash
nemoclaw sandbox delete my-sandbox
```

This also removes any active port forwards.
