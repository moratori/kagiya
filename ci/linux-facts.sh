#!/bin/sh
# コンテナ内で実行する。ディストリビューションの実物から、kagiya のルールとテストの根拠になる事実を採取する。
# 使い方: linux-facts.sh <出力ディレクトリ>
# 手元の検証ラボと GitHub Actions（.github/workflows/linux-facts.yml）の両方から使う。
set -u
O=$1
rm -rf "$O"; mkdir -p "$O/conf"
exec >"$O/run.log" 2>&1

save() { # save <名前> <コマンド...>  標準出力と標準エラーを1つのファイルに残す
  n=$1; shift
  { echo "\$ $*"; "$@"; echo "[exit=$?]"; } >"$O/$n" 2>&1
}
keep() { # keep <ファイル>  設定ファイルをパスを保ったまま写す
  for f in "$@"; do
    [ -e "$f" ] || continue
    mkdir -p "$O/conf$(dirname "$f")"; cp -a "$f" "$O/conf$f" 2>/dev/null
  done
}

cp /etc/os-release "$O/os-release"
uname -srm >"$O/uname.txt"

# ---- 導入前の状態（素のイメージ） ----
STORE_DIRS="/etc/ssl /etc/pki /usr/share/ca-certificates /usr/local/share/ca-certificates /usr/share/pki /etc/ca-certificates /etc/ca-certificates.conf"
save store-before.txt sh -c "for d in $STORE_DIRS; do [ -e \$d ] && find \$d -maxdepth 5 \( -type f -o -type l \) -exec ls -l {} + ; done 2>/dev/null | awk '{print \$1, \$5, \$9, \$10, \$11}' | head -600"

# ---- パッケージの導入 ----
if command -v apt-get >/dev/null; then
  FAMILY=deb
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq --no-install-recommends openssl ca-certificates openssh-server openssh-client nginx apache2 binutils file
elif command -v dnf >/dev/null; then
  FAMILY=rpm
  dnf -y -q install openssl ca-certificates openssh-server openssh-clients nginx httpd mod_ssl binutils file crypto-policies-scripts findutils
elif command -v microdnf >/dev/null; then
  FAMILY=rpm
  microdnf -y install openssl ca-certificates openssh-server openssh-clients nginx httpd mod_ssl binutils file crypto-policies-scripts findutils
else
  echo "unknown package manager"; exit 1
fi
echo "$FAMILY" >"$O/family.txt"

# ---- パッケージの版とパッケージ DB ----
if [ "$FAMILY" = deb ]; then
  save packages.txt sh -c "dpkg-query -W -f='\${Package}\t\${Version}\t\${Architecture}\t\${Status}\n' | grep -E '^(openssl|libssl|libgnutls|libnss3|libgcrypt|openssh|nginx|apache2|ca-certificates|libc6)'"
  save pkgdb.txt sh -c "ls -la /var/lib/dpkg | head -30; echo; grep -c '^Package:' /var/lib/dpkg/status; echo; awk '/^Package: openssl\$/,/^\$/' /var/lib/dpkg/status"
else
  save packages.txt sh -c "rpm -qa --qf '%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{ARCH}\t%{VENDOR}\n' | grep -E '^(openssl|gnutls|nss|libgcrypt|openssh|nginx|httpd|mod_ssl|ca-certificates|crypto-policies|glibc)' | sort"
  save pkgdb.txt sh -c "rpm --eval 'db_backend=%{_db_backend} dbpath=%{_dbpath}'; ls -la /var/lib/rpm /usr/lib/sysimage/rpm 2>&1; for f in /var/lib/rpm/Packages /var/lib/rpm/rpmdb.sqlite /var/lib/rpm/Packages.db /usr/lib/sysimage/rpm/rpmdb.sqlite; do [ -f \$f ] && { echo \"== \$f\"; file \$f; od -A d -t x1 -N 32 \$f; }; done"
fi

# ---- 証明書ストア（導入後） ----
save store-after.txt sh -c "for d in $STORE_DIRS; do [ -e \$d ] && find \$d -maxdepth 5 \( -type f -o -type l \) -exec ls -l {} + ; done 2>/dev/null | awk '{print \$1, \$5, \$9, \$10, \$11}' | head -1200"
save store-summary.txt sh -c "for d in /etc/ssl/certs /etc/ssl/private /etc/pki/tls/certs /etc/pki/tls/private /etc/pki/ca-trust/source/anchors /etc/pki/ca-trust/extracted/pem /etc/pki/ca-trust/extracted/openssl /etc/pki/ca-trust/extracted/java /etc/pki/ca-trust/extracted/pem/directory-hash /usr/share/ca-certificates /usr/local/share/ca-certificates /usr/share/pki/ca-trust-source /etc/pki/java; do if [ -e \$d ]; then echo \"\$d: files=\$(find \$d -maxdepth 1 -type f | wc -l) symlinks=\$(find \$d -maxdepth 1 -type l | wc -l) dirs=\$(find \$d -mindepth 1 -maxdepth 1 -type d | wc -l)\"; else echo \"\$d: (none)\"; fi; done; echo; for f in /etc/ssl/certs/ca-certificates.crt /etc/ssl/cert.pem /etc/pki/tls/cert.pem /etc/pki/tls/certs/ca-bundle.crt /etc/pki/tls/certs/ca-bundle.trust.crt /etc/ssl/certs/ca-bundle.crt /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem /etc/pki/ca-trust/extracted/java/cacerts /etc/pki/java/cacerts; do if [ -e \$f ] || [ -L \$f ]; then echo \"\$f -> \$(readlink -f \$f) certs=\$(grep -c 'BEGIN' \$f 2>/dev/null)\"; else echo \"\$f: (none)\"; fi; done"

# ---- OpenSSL ----
save openssl-version.txt openssl version -a
OPENSSLDIR=$(openssl version -d | sed 's/.*"\(.*\)"/\1/')
keep "$OPENSSLDIR/openssl.cnf" /etc/ssl/openssl.cnf /etc/pki/tls/openssl.cnf
[ -d /etc/pki/tls/openssl.d ] && keep /etc/pki/tls/openssl.d/*
save openssl-ciphers-default.txt openssl ciphers -v
save openssl-ciphers-all.txt openssl ciphers -V 'ALL:COMPLEMENTOFALL'
save openssl-ciphers-profile.txt openssl ciphers -v 'PROFILE=SYSTEM'
save openssl-ciphers-high.txt openssl ciphers -v 'HIGH:!aNULL:!MD5'

# ---- システム全体の暗号ポリシー ----
if [ -d /etc/crypto-policies ]; then
  save crypto-policies.txt sh -c "echo '== config'; cat /etc/crypto-policies/config; echo '== state/current'; cat /etc/crypto-policies/state/current 2>&1; echo '== show'; update-crypto-policies --show 2>&1; echo '== back-ends'; ls -la /etc/crypto-policies/back-ends/; echo '== policies'; ls /usr/share/crypto-policies/ /usr/share/crypto-policies/policies 2>&1"
  mkdir -p "$O/conf/etc/crypto-policies/back-ends"
  for f in /etc/crypto-policies/back-ends/*; do cp -L "$f" "$O/conf/etc/crypto-policies/back-ends/" 2>/dev/null; done
  keep /etc/crypto-policies/config /etc/crypto-policies/state/current
else
  echo "no /etc/crypto-policies" >"$O/crypto-policies.txt"
fi
save fips.txt sh -c "cat /proc/sys/crypto/fips_enabled 2>&1"

# ---- OpenSSH ----
ssh-keygen -A >/dev/null 2>&1
mkdir -p /run/sshd /var/empty/sshd
SSHD=$(command -v sshd || echo /usr/sbin/sshd)
save ssh-version.txt sh -c "ssh -V; $SSHD -V 2>&1 | head -3"
save sshd-T.txt "$SSHD" -T
# 既定値（設定が空のときに sshd 自身が報告する値）。パッケージ版ごとの既定値表のもとになる
: >/tmp/empty_sshd_config
save sshd-T-bare.txt "$SSHD" -T -f /tmp/empty_sshd_config
save ssh-Q.txt sh -c "for q in cipher cipher-auth mac kex kex-gss key key-cert key-plain key-sig sig HostKeyAlgorithms PubkeyAcceptedAlgorithms PubkeyAcceptedKeyTypes; do echo \"== \$q\"; ssh -Q \$q 2>&1; done"
keep /etc/ssh/sshd_config /etc/ssh/ssh_config /etc/sysconfig/sshd /etc/default/ssh
for f in /etc/ssh/sshd_config.d/* /etc/ssh/ssh_config.d/*; do keep "$f"; done
save sshd-units.txt sh -c "for f in /usr/lib/systemd/system/sshd.service /lib/systemd/system/ssh.service /usr/lib/systemd/system/sshd@.service /usr/lib/systemd/system/ssh@.service; do [ -f \$f ] && { echo \"== \$f\"; cat \$f; }; done"
save ssh-hostkeys.txt sh -c "ls -l /etc/ssh/ | awk '{print \$1, \$5, \$9}'"

# ---- nginx ----
save nginx-V.txt nginx -V
save nginx-T.txt nginx -T
keep /etc/nginx/nginx.conf
for f in /etc/nginx/conf.d/* /etc/nginx/sites-enabled/* /etc/nginx/sites-available/* /etc/nginx/default.d/* /etc/nginx/snippets/*; do keep "$f"; done

# ---- Apache httpd ----
if [ "$FAMILY" = deb ]; then
  save httpd-V.txt sh -c ". /etc/apache2/envvars; apache2 -V; echo; apache2 -v"
  save httpd-M.txt sh -c "a2enmod -q ssl >/dev/null 2>&1; . /etc/apache2/envvars; apache2 -M"
  keep /etc/apache2/apache2.conf /etc/apache2/mods-available/ssl.conf /etc/apache2/mods-available/ssl.load /etc/apache2/sites-available/default-ssl.conf /etc/apache2/ports.conf
else
  save httpd-V.txt sh -c "httpd -V; echo; httpd -v"
  save httpd-M.txt httpd -M
  keep /etc/httpd/conf/httpd.conf /etc/httpd/conf.d/ssl.conf /etc/httpd/conf.modules.d/00-ssl.conf
fi

# ---- バイナリ: リンクしているライブラリと、埋め込まれた版文字列 ----
{
  for name in sshd ssh nginx httpd apache2 openssl; do
    b=$(command -v $name 2>/dev/null) || continue
    b=$(readlink -f "$b")
    echo "=================== $name => $b"
    file "$b" | sed 's/^/file: /'
    echo "-- DT_NEEDED / RPATH / RUNPATH"
    readelf -d "$b" 2>/dev/null | grep -E 'NEEDED|RPATH|RUNPATH' | sed 's/^ */  /'
    echo "-- ldd"
    ldd "$b" 2>&1 | grep -E 'ssl|crypto|gnutls|nss|gcrypt|libc\.so|fips' | sed 's/^[ \t]*/  /'
    echo "-- 埋め込まれた版文字列"
    grep -a -o -E 'OpenSSH_[0-9][0-9A-Za-z._-]*|nginx/[0-9]+\.[0-9]+\.[0-9]+|Apache/[0-9]+\.[0-9]+\.[0-9]+[^"]{0,24}|OpenSSL [0-9]+\.[0-9]+\.[0-9]+[a-z]*( *-?fips)? +[0-9]+ [A-Z][a-z]+ [0-9]{4}' "$b" | sort -u | head -8 | sed 's/^/  /'
  done
  echo "=================== 暗号ライブラリ本体"
  for lib in $(ldd "$(command -v openssl)" 2>/dev/null | awk '/libssl|libcrypto/{print $3}') ; do
    real=$(readlink -f "$lib")
    echo "$lib -> $real"
    grep -a -o -E 'OpenSSL [0-9]+\.[0-9]+\.[0-9]+[a-z]*( *-?fips)? +[0-9]+ [A-Z][a-z]+ [0-9]{4}' "$real" | sort -u | head -3 | sed 's/^/  version string: /'
    readelf -d "$real" 2>/dev/null | grep -E 'SONAME' | sed 's/^ */  /'
  done
  echo "=================== 動的リンカの設定"
  ls -l /etc/ld.so.cache 2>&1; cat /etc/ld.so.conf 2>&1; ls /etc/ld.so.conf.d/ 2>&1
} >"$O/binaries.txt" 2>&1

chmod -R a+rX "$O"
echo "done: $O"
