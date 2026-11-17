# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Background jobs for the MCP exec and wait tools (RFC 0021). The gateway runs
# this script in a child sandbox through ExecSandbox, as
#   sh -c "$script" sh <action> <root> <arguments...>
#   start  <root> <token> <has_stdin> <command...>
#   check  <root> <n> <token>
#   output <root> <n> <token> <edge_bytes>
# The command arrives as arguments and runs as "$@"; it is never part of this
# text. Each job lives in <root>/<n>/: id, pid, stdin, out, err, exit.

# A START claims a folder before it writes its pid; one with no pid this much
# older than now has lost its START.
claim_window_s=10

action=$1
root=$2
shift 2

# Helpers this shell and each job's own shell both use.
# shellcheck disable=SC2016 # expanded where the text is run
helpers='
# Write a whole file at once, so a reader sees all of it or none of it. The
# temporary name is per writer, as two shells may write one file.
write_file() {
    printf "%s\n" "$2" > "$1.$$.tmp" && mv -f "$1.$$.tmp" "$1"
}

# Field 22 of /proc/<pid>/stat: when the process started. The process name
# before it may hold spaces and parentheses, so cut through its last ") ".
start_time() {
    proc_stat=$(cat "/proc/$1/stat" 2>/dev/null) || return 1
    set -- ${proc_stat##*") "}
    [ $# -ge 20 ] || return 1
    printf "%s\n" "${20}"
}
'
eval "$helpers"

# running, completed or lost.
job_state() {
    if [ -f "$1/exit" ]; then
        echo completed
        return
    fi
    if [ ! -f "$1/pid" ]; then
        claimed=$(stat -c %Y "$1" 2>/dev/null || echo 0)
        if [ $(($(date +%s) - claimed)) -le "$claim_window_s" ]; then
            echo running
        else
            echo lost
        fi
        return
    fi
    pid='' started=''
    read -r pid started < "$1/pid"
    if [ -n "$pid" ] && [ -n "$started" ] && [ "$(start_time "$pid")" = "$started" ]; then
        echo running
    else
        echo lost
    fi
}

numbered_jobs() {
    # shellcheck disable=SC2010 # only all-digit names pass the filter
    ls "$root" | grep -E '^[0-9]+$'
}

# The first and last <edge> bytes of a file, or all of it when it is small.
edges() {
    size=$(wc -c < "$1")
    if [ "$size" -le $(($2 * 2)) ]; then
        cat "$1"
    else
        head -c "$2" "$1"
        tail -c "$2" "$1"
    fi
}

case $action in
start)
    token=$1 has_stdin=$2
    shift 2
    # Jobs need a writable root, and wait needs /proc and stat. Each cause
    # is named, so the caller can say which one to fix.
    if ! mkdir -p "$root" 2>/dev/null || [ ! -w "$root" ]; then
        echo unusable tmp
        exit 0
    fi
    if ! start_time $$ > /dev/null; then
        echo unusable proc
        exit 0
    fi
    if ! stat -c %Y "$root" > /dev/null 2>&1; then
        echo unusable stat
        exit 0
    fi
    last=$(numbered_jobs | sort -n | tail -n 1)
    if [ -n "$last" ] && [ "$(job_state "$root/$last")" = running ]; then
        echo "busy $last $(cat "$root/$last/id" 2> /dev/null)"
        exit 0
    fi
    n=$((${last:-0} + 1))
    job=$root/$n
    # Of two starts, exactly one makes the folder.
    if ! mkdir "$job" 2> /dev/null; then
        echo "busy $n $(cat "$job/id" 2> /dev/null)"
        exit 0
    fi
    write_file "$job/id" "$token"
    # Until the job runs, this shell stands in for it.
    write_file "$job/pid" "$$ $(start_time $$)"
    if [ "$has_stdin" = 1 ]; then
        cat > "$job/stdin"
    else
        : > "$job/stdin"
    fi
    # The job lets go of the exec's stdin, stdout and stderr, or the exec
    # would not end until the job does.
    setsid=$(command -v setsid || true)
    # The job records its own pid first, so it reads as running even if
    # this shell is killed before its own record below lands. Both write
    # the same pid.
    # shellcheck disable=SC2016 # expanded by the job's own shell
    $setsid sh -c "$helpers"'
        job=$1
        shift
        write_file "$job/pid" "$$ $(start_time $$)"
        "$@" < "$job/stdin" > "$job/out" 2> "$job/err"
        printf "%s\n" "$?" > "$job/exit.tmp" && mv -f "$job/exit.tmp" "$job/exit"
    ' sh "$job" "$@" < /dev/null > /dev/null 2>&1 &
    write_file "$job/pid" "$! $(start_time $!)"
    # A job's result can be read until the next job starts.
    for old in $(numbered_jobs); do
        [ "$old" -lt "$n" ] && rm -rf "${root:?}/$old"
    done
    echo "started $n"
    ;;
check)
    job=$root/$1
    if [ "$(cat "$job/id" 2> /dev/null)" != "$2" ]; then
        echo missing
        exit 0
    fi
    state=$(job_state "$job")
    if [ "$state" = completed ]; then
        echo "completed $(cat "$job/exit") $(wc -c < "$job/out") $(wc -c < "$job/err")"
    else
        echo "$state"
    fi
    ;;
output)
    job=$root/$1
    [ "$(cat "$job/id" 2> /dev/null)" = "$2" ] || exit 3
    edges "$job/out" "$3"
    edges "$job/err" "$3" >&2
    ;;
*)
    exit 2
    ;;
esac
