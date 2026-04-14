How does colorsaurus detect if a terminal supports querying its colors?

Colorsaurus sends two escape sequences: `OSC 10` (or `OSC 11`) followed by `DA1`.
`DA1` is supported by almost every terminal.

Terminals process incoming escape sequences in order.
Therefore if the response to `DA1` is seen first, then the terminal does not support `OSC 10` (or `OSC 11`).

Colorsaurus thus doesn't need to rely on a timeout to detect if a terminal supports `OSC 10` (or `OSC 11`).

However, there might still be a lot of latency (e.g. when connected via SSH) or the terminal might not support `DA1`.
To prevent waiting forever in those cases, colorsaurus uses a 1 second timeout by default.
