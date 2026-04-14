## Caveats

Extra care needs to be taken on Unix if your program might share
the terminal with another program. This might be the case
if you expect your output to be used with a pager e.g. `your_program` | `less`.
In that case, a race condition exists because the pager will also set the terminal to raw mode.
The `pager` example shows a heuristic to deal with this issue.
