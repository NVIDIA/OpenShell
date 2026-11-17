#!/bin/sh

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Scenarios for jobs.sh, run by the jobs tests on Linux (it needs /proc):
#   sh jobs_test.sh /path/to/jobs.sh
# Prints one line per check and "ALL OK" when every check passed.
S=$(cat "$1")
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
R=$T/jobs
fail=0
j() { sh -c "$S" sh "$@"; }
ok() { if [ "$1" = "$2" ]; then echo "ok   $3"; else echo "FAIL $3: got [$1] want [$2]"; fail=1; fi; }

t0=$(date +%s)
out=$(j start $R aaaaaaaa 0 sh -c 'sleep 3; echo hi; echo err >&2; exit 7')
t1=$(date +%s)
ok "$out" "started 1" "start"
ok "$([ $((t1 - t0)) -le 1 ] && echo fast)" fast "start returns at once"
ok "$(j check $R 1 aaaaaaaa)" running "running"
ok "$(j start $R bbbbbbbb 0 true)" "busy 1 aaaaaaaa" "second start refused"
ok "$(j check $R 1 cccccccc)" missing "wrong token is missing"
sleep 4
ok "$(j check $R 1 aaaaaaaa)" "completed 7 3 4" "completed"
ok "$(j output $R 1 aaaaaaaa 16384 2>/dev/null)" "hi" "output stdout"
ok "$(j output $R 1 aaaaaaaa 16384 2>&1 >/dev/null)" "err" "output stderr"

# quoting and stdin
ok "$(printf 'in put' | j start $R dddddddd 1 sh -c 'cat; printf "|%s" "$@"' x "a b" "\$HOME" "x;y" "'q'")" "started 2" "start with stdin"
sleep 1
ok "$(j check $R 2 dddddddd)" "completed 0 24 0" "quoting done"
ok "$(j output $R 2 dddddddd 16384 2>/dev/null)" "in put|a b|\$HOME|x;y|'q'" "args and stdin intact"
ok "$([ -d $R/1 ] && echo kept || echo gone)" gone "older job removed"

# empty stdin
j start $R eeeeeeee 0 sh -c 'wc -c' >/dev/null; sleep 1
ok "$(j output $R 3 eeeeeeee 16384 2>/dev/null | tr -d ' ')" "0" "no stdin is empty"

# signal and kill -> lost
j start $R ffffffff 0 sh -c 'kill -TERM $$' >/dev/null; sleep 1
ok "$(j check $R 4 ffffffff | cut -d' ' -f1-2)" "completed 143" "killed by signal"
j start $R gggggggg 0 sleep 30 >/dev/null
read -r p s < $R/5/pid
kill -9 "$p"; sleep 1
ok "$(j check $R 5 gggggggg)" lost "killed job is lost"
ok "$(j start $R hhhhhhhh 0 true)" "started 6" "lost job frees the slot"

# reused pid: alive pid, wrong start time
sleep 1
mkdir $R/7 && echo iiiiiiii > $R/7/id && echo "$$ 1" > $R/7/pid
ok "$(j check $R 7 iiiiiiii)" lost "alive pid with other start time is lost"
rm -rf $R/7

# claim window: folder without pid
mkdir $R/7 && echo jjjjjjjj > $R/7/id
ok "$(j start $R kkkkkkkk 0 true)" "busy 7 jjjjjjjj" "fresh claim without pid blocks"
touch -d '@'$(( $(date +%s) - 11 )) $R/7
ok "$(j start $R kkkkkkkk 0 true)" "started 8" "old claim without pid is lost"
# empty pid file
mkdir $R/9 && echo llllllll > $R/9/id && : > $R/9/pid
ok "$(j check $R 9 llllllll)" lost "empty pid file is lost"
rm -rf $R/9

# two starts at once: exactly one wins
sleep 1
for i in 1 2 3 4 5 6; do j start $R mmmmmmm$i 0 sleep 5 > $T/race$i & done; wait
ok "$(cat $T/race* | grep -c started)" 1 "one of six racing starts wins"

# big output capped
sleep 6
j start $R nnnnnnnn 0 sh -c 'head -c 100000 /dev/zero | tr "\0" a' >/dev/null; sleep 1
n=$(ls $R | sort -n | tail -n1)
ok "$(j output $R $n nnnnnnnn 16384 2>/dev/null | wc -c | tr -d ' ')" 32768 "output capped to both edges"

# START killed after spawning the job, before recording its pid. A stand-in
# mv, on PATH for this start only, kills any writer that records another
# process's pid as a job's pid, just before the record lands.
mkdir $T/shim
cat > $T/shim/mv <<'EOF'
#!/bin/sh
[ "$1" = -f ] && shift
case $2 in
*/pid)
    read -r p _ < "$1"
    if [ "$p" != "$PPID" ]; then kill -9 "$PPID"; exit 1; fi
    ;;
esac
exec /bin/mv "$@"
EOF
chmod +x $T/shim/mv
sleep 1
(PATH=$T/shim:$PATH j start $R pppppppp 0 sleep 4) > /dev/null 2>&1
n=$(ls $R | sort -n | tail -n1)
ok "$(j check $R $n pppppppp)" running "job outlives a START killed before recording it"
ok "$(j start $R qqqqqqqq 0 true)" "busy $n pppppppp" "and keeps its slot"
sleep 4
ok "$(j check $R $n pppppppp | cut -d' ' -f1-2)" "completed 0" "and completes"

# unusable root
ok "$(j start /proc/nope oooooooo 0 true)" "unusable tmp" "unwritable root"
[ $fail = 0 ] && echo ALL OK
