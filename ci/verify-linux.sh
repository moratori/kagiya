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

# 4. 探索の後のフェーズ（JAR を開く処理）でも、中断と時間制限が効く
# 末尾に zip の終わりの記録だけを持つ、中身のない JAR を多数置く。探索では中身を読まないのですぐ終わり、その後、1 つずつ開く処理が
# 読み取り速度の上限（1 MiB/秒）のもとで長く続く。その間にシグナルを送る
mkdir -p "$W/jars"
head -c 65536 /dev/zero > "$W/jar.body"; printf 'PK\005\006\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000' >> "$W/jar.body"
i=0; while [ $i -lt 1500 ]; do cp "$W/jar.body" "$W/jars/a$i.jar"; i=$((i+1)); done
"$K" scan --roots "$W/jars" --output-dir "$W/out4" --log-dir "$W/logs4" --cpu-limit 100 --io-limit 1 2>"$W/err4" &
PID=$!
sleep 4
T0=$(date +%s); kill -TERM $PID; wait $PID; RC=$?; T1=$(date +%s)
echo "stopped in $((T1-T0))s with exit code $RC: $(cat "$W/err4")"
check "JAR を開く処理の途中でも、SIGTERM で終了コード 3" "[ $RC -eq 3 ]"
check "数秒以内に止まる"                               "[ $((T1-T0)) -le 5 ]"
check "探索は終わっていた（JAR の処理の途中で止めた）"   "grep -q '\"files_examined\": 1500' \"$W\"/out4/*.json"
check "結果に、中断による未完了と記録される"           "grep -q '\"incomplete_reason\": \"interrupted\"' \"$W\"/out4/*.json"
check "ログは最終名で残る"                             "ls \"$W\"/logs4/*.log >/dev/null 2>&1 && ! ls \"$W\"/logs4/*.partial >/dev/null 2>&1"
T0=$(date +%s)
"$K" scan --roots "$W/jars" --output-dir "$W/out5" --log-dir "$W/logs5" --cpu-limit 100 --io-limit 1 --max-duration 3s 2>"$W/err5"; RC=$?
T1=$(date +%s)
echo "finished in $((T1-T0))s with exit code $RC: $(cat "$W/err5")"
check "--max-duration は、探索の後のフェーズにも効く（終了コード 3）" "[ $RC -eq 3 ]"
check "時間制限から数秒以内に終わる"                               "[ $((T1-T0)) -le 9 ]"
check "結果に、時間制限による未完了と記録される" "grep -q '\"incomplete_reason\": \"max-duration\"' \"$W\"/out5/*.json"
# SIGHUP（接続が切れたとき）でも、途中の結果を書いて終わる
"$K" scan --roots "$W/jars" --output-dir "$W/out6" --log-dir "$W/logs6" --cpu-limit 100 --io-limit 1 2>"$W/err6" &
PID=$!
sleep 3; kill -HUP $PID; wait $PID
check "SIGHUP で終了コード 3（未完了）" "[ $? -eq 3 ]"
check "SIGHUP でも結果が書かれる"       "grep -q '\"completed\": false' \"$W\"/out6/*.json"

[ $fail -eq 0 ] && echo "ALL OK" || echo "SOME CHECKS FAILED"
exit $fail
