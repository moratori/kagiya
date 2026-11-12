#!/bin/sh
# kagiya の安全策が実際の Linux 上で働くことを確認し、1つでも満たさなければ失敗する。
# 使い方: verify-host.sh <kagiya のパス> <作業ディレクトリ> [nostrace]
# CI（GitHub Actions のランナー上、および各ディストリのコンテナ内）から呼ぶ。Linux 専用。
set -u
K=$1; W=$2; MODE=${3:-strace}
fail=0
ok()   { echo "ok   - $1"; }
ng()   { echo "FAIL - $1"; fail=1; }
check(){ if eval "$2"; then ok "$1"; else ng "$1"; fi; }

rm -rf "$W"; mkdir -p "$W/tree/sub"
echo "kernel=$(uname -r) machine=$(uname -m) uid=$(id -u)"; grep PRETTY_NAME /etc/os-release || true
"$K" version || ng "version"

# 読み取りに時間がかかるよう、証明書の拡張子を持つファイルを多数用意する
i=0; while [ $i -lt 300 ]; do head -c 16384 /dev/zero | tr '\0' 'x' > "$W/tree/sub/f$i.pem"; i=$((i+1)); done
ROOTS=/etc
[ -d /usr/share/ca-certificates ] && ROOTS=/etc,/usr/share/ca-certificates

# 1. 通常のスキャン
"$K" scan --roots "$ROOTS" --output-dir "$W/out" --log-dir "$W/logs" --cpu-limit 100 --io-limit 0
check "scan が正常終了する" "[ $? -eq 0 ]"
R=$(ls "$W"/out/*.json 2>/dev/null | head -1)
check "結果ファイルができる" "[ -n \"$R\" ]"
sed -n '/"hardening"/,/}/p' "$R"
check "優先度が下がっている"         "grep -q '\"priority_lowered\": true' \"$R\""
check "コアダンプが無効化されている" "grep -q '\"core_dump_disabled\": true' \"$R\""
check "seccomp が適用されている"     "grep -q '\"seccomp\": \"applied\"' \"$R\""
check "結果ファイルの権限が 0600"    "[ \"\$(stat -c %a \"$R\")\" = 600 ]"
check "ログファイルの権限が 0600"    "[ \"\$(stat -c %a \"$W\"/logs/*.log)\" = 600 ]"
check "出力ディレクトリの権限が 0700" "[ \"\$(stat -c %a \"$W/out\")\" = 700 ]"

# 2. 実行中プロセスの状態を、プロセスの外から確認する
"$K" scan --roots "$W/tree" --output-dir "$W/out2" --log-dir "$W/logs2" --cpu-limit 50 --io-limit 1 2>"$W/err2" &
PID=$!
sleep 2
check "実行中に seccomp フィルタが有効（Seccomp: 2）" "grep -q '^Seccomp:[[:space:]]*2' /proc/$PID/status"
check "NoNewPrivs が有効"                              "grep -q '^NoNewPrivs:[[:space:]]*1' /proc/$PID/status"
NICES=$(for t in /proc/$PID/task/*; do cut -d' ' -f19 "$t/stat"; done | sort -u | tr '\n' ' ')
echo "nice values of all threads: $NICES"
check "全スレッドの nice が 19" "[ \"$NICES\" = '19 ' ]"
check "コアファイルの上限が 0"  "grep -qE 'Max core file size +0 +0' /proc/$PID/limits"
kill -TERM $PID; wait $PID
check "SIGTERM で終了コード 3（未完了）" "[ $? -eq 3 ]"
check "結果に未完了と記録される" "grep -q '\"completed\": false' \"$W\"/out2/*.json"

# 3. システムコールの確認
if [ "$MODE" = strace ] && command -v strace >/dev/null; then
  strace -f -o "$W/strace.txt" -e trace=network,execve,execveat,ptrace \
    "$K" scan --roots "$ROOTS" --output-dir "$W/out3" --log-dir "$W/logs3" --cpu-limit 100 --io-limit 0
  check "strace 下でも正常終了する" "[ $? -eq 0 ]"
  NET=$(grep -cE '(socket|connect|bind|listen|accept4?|sendto|sendmsg|recvfrom|recvmsg|socketpair)\(' "$W/strace.txt")
  EXE=$(grep -c 'execve' "$W/strace.txt")
  echo "network syscalls: $NET, execve: $EXE"
  check "通信系システムコールが 0 回"        "[ \"$NET\" = 0 ]"
  check "プロセス起動は自身の起動時の 1 回のみ" "[ \"$EXE\" = 1 ]"
fi

[ $fail -eq 0 ] && echo "ALL OK" || echo "SOME CHECKS FAILED"
exit $fail
