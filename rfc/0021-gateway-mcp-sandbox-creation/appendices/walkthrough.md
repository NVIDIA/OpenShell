# Appendix: End-to-End Walkthrough

> This is an appendix to the [RFC](../README.md). Please familiarize yourself with the RFC before reading this.

A lead agent creates a worker, hands it a task, follows a policy change and cleans up.

1. **The operator enables the feature.**

   ```toml
   [openshell.gateway]
   experimental_enable_child_sandboxes = true
   max_concurrent_children = 10
   ```

2. **A user starts a lead.**

   ```shell
   openshell sandbox create --name lead --from pi-agent:local \
     --provider nvidia --policy team.yaml -- pi
   ```

3. **The agent creates a worker.** Pi calls `create_sandbox {name: "worker"}` at
   `http://openshell.local/mcp`. The supervisor attaches `lead`'s token. The
   gateway checks that children are enabled, that `lead` is a root under its
   limit, and that the user who created `lead` is still a member of the
   workspace. It creates `worker` with `lead`'s image, CPU, memory and providers
   and a copy of `lead`'s policy, and returns once `worker` is ready.

4. **The agent hands it a task.**
   `exec {name: "worker", command: ["pi", "-p", "Write the tests"], background: true}`
   returns job `1-9f2c41ab`. The agent calls
   `wait {name: "worker", job: "1-9f2c41ab"}` until it returns the exit code
   and the worker's answer on stdout.

5. **The user changes the lead's policy.** `openshell policy set lead ...`
   creates `lead` version 8. The gateway copies it into `worker` and delivers
   it; `worker` applies it within seconds.

6. **The agent cleans up.** `delete {name: "worker"}` frees the slot. Later the
   user runs `openshell sandbox delete lead`, which succeeds because `lead` has
   no children left.
