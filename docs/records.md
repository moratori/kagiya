# kagiya 実測と実装の記録

設計書（[design.md](./design.md)）が「いまの方針と設計」を示すのに対し、この文書は「何を実物で確かめ、どう実装してきたか」の記録。
既定値や対応表の根拠になった測定、差分テストの結果、利用者の指摘とその反映、進み具合を、対象ごとにまとめている。
各節の日付は、その内容を確かめた日。分かっている限界は [limitations.md](./limitations.md) にまとめている。

2026-11-14 に、設計書から記録の部分を分けて作った（各節の文面は、移したときのまま）。

---

## 1. 検証ラボと CI

### 検証ラボについて

実物（各ディストリのパッケージ、実際の挙動）を確かめるための検証ラボを、開発者の手元の `lab/` ディレクトリに置いている。
ラボはリポジトリに含めない（`.gitignore` で除外）。本体からは参照せず、ラボで得た事実とその出典だけをルール・テストデータ・本書に反映する。
リポジトリ内で再現できる検証は、CI（`.github/workflows/ci.yml` と `ci/verify-linux.sh`）で行う。

### Phase 0 のラボ検証の結果（2026-11-12）

環境: Docker Desktop 29.9.3（Apple M1）、コンテナのカーネルは `7.0.14-linuxkit`（arm64）。
コンテナは Docker の VM のカーネルを共有するため、確認できたのは各ディストリのユーザーランド上での動作であり、各ディストリ本来のカーネル上での動作ではない。

| イメージ | ダイジェスト | OS |
|---|---|---|
| `ubuntu:16.04` | `sha256:1f1a2d56de1d604801a9671f301190704c25d604a416f59e03c04f5c6ffee0d6` | Ubuntu 16.04.7 LTS |
| `ubuntu:24.04` | `sha256:2198e4c65076e9cb0b3d695219df667c0e3b0072da64ca3c2648aca17dcecaf5` | Ubuntu 24.04.5 LTS |
| `redhat/ubi8` | `sha256:44f19e308462e9152cb26d641fc0ce5bf6cbdab3cd101367aed67573eb2cf20e` | RHEL 8.10 |
| `redhat/ubi9` | `sha256:8b212f75a0e5a156ac28b1c5c030d2e8a07715254e19d522286118279399af81` | RHEL 9.9 |

4イメージすべて（arm64 ネイティブ）で確認できたこと:

| 項目 | 結果 |
|---|---|
| 起動（`version`、`scan`） | 動作 |
| 優先度低下 | 全スレッド（8〜9本）が nice 19 |
| seccomp | 実行中プロセスが `Seccomp: 2`、`NoNewPrivs: 1` |
| コアダンプ無効化 | コアファイルの上限が 0 |
| 通信・プロセス起動系システムコール | strace（4.11 / 5.18 / 6.8 / 6.12）で 0 回。`execve` は起動時の 1 回のみ |
| 分類表にないファイルシステム（Docker のバインドマウント、種別 `fakeowner`） | そこからの起動・そこへの出力は拒否、スキャンでは読まずに `unknown-fs` として記録 |
| 出力・ログの権限 | 0600 |
| SIGTERM | 安全に停止し、結果に未完了と記録、終了コード 3 |
| 一般ユーザー（UID 65534）での実行 | 同じ結果（Ubuntu 24.04 で確認） |
| 実物の証明書 | Ubuntu 16.04 で 129 件、UBI 8 / 9 で 404 件を解析エラーなしで読み取り |

見つかった問題:

1. 信頼設定付き証明書（`BEGIN TRUSTED CERTIFICATE`）を読めなかった（修正済み）。実物は RHEL 8.10 / 9.9 の `/etc/pki/ca-trust/extracted/openssl/ca-bundle.trust.crt`。証明書の後ろに補助データが続く形式。
2. amd64 の seccomp フィルタは手元では検証できない。amd64 イメージ（Rosetta 2 によるエミュレーション）では `seccomp` システムコール自体が `EINVAL` で失敗する。kagiya は失敗を記録して処理を続行した。amd64 の実カーネルでの確認は CI の `linux-host` ジョブで行う。

未確認: 各ディストリ本来のカーネル上での動作、実際の NFS / SMB / autofs マウントのスキップ、負荷試験による流量制限の既定値の妥当性。

### CI での確認（2026-11-12）

GitHub Actions の全16ジョブが成功した（リポジトリ所有者からの報告による）。これにより次の点が確認できた。

- amd64 の実カーネル（Ubuntu 22.04 / 24.04 のランナー）で、seccomp の適用、全スレッドの優先度低下、コアダンプ無効化、出力の権限、strace での通信系システムコール 0 回
- Ubuntu 16.04 / 20.04 / 24.04、UBI 8 / 9、Rocky Linux 8、Debian 13 のコンテナ（amd64）での同じ検証（strace を除く）
- Windows Server 2022 / 2025 での単体テスト（OS に依存しない部分）、ビルド、起動、`scan` が書き込まずに拒否されること

引き続き未確認: 各ディストリ本来のカーネル（RHEL 8 の 4.18、Ubuntu 16.04 の 4.4）上での動作、Windows Server 2016 / 2019、実際の NFS / SMB / autofs マウントのスキップ。

### 15 ディストリビューション（amd64）からの採取（2026-11-12、GitHub Actions）

`.github/workflows/linux-facts.yml`（`ci/linux-facts.sh`）で、各イメージに OpenSSL・OpenSSH・nginx・Apache httpd を導入して採取した。
パッケージ版は採取時点で各ディストリのリポジトリから導入されたもの（エポックは省略）。Debian 11 はパッケージの取得に失敗した（セキュリティ更新のリポジトリが 404 を返した）ため、表では「-」としている。

| OS | イメージ（ダイジェスト） | openssl | openssh-server | nginx | Apache httpd | パッケージ DB | 暗号ポリシー |
|---|---|---|---|---|---|---|---|
| AlmaLinux 8.10 (Cerulean Leopard) | `almalinux@sha256:2d0f2eb2a83cc09dbc2eb92fade4dbe8f709628149e81aa00aec70630406603b` | `1.1.1k-18.el8_6` | `8.0p1-34.el8_10` | `1.14.1-9.module_el8.10.0+4171+d7eec01b.alma.1` | `2.4.37-65.module_el8.10.0+4332+2bef2e0d.13` | rpm（Berkeley DB） | DEFAULT |
| AlmaLinux 9.8 (Olive Jaguar) | `almalinux@sha256:245f8aab832fe800aa42bdab5fad75ebbd8e0b4c9f24820a83c638b177857ae2` | `3.5.8-2.el9_8` | `9.9p1-13.el9_8.alma.1` | `1.20.1-28.el9_8.6.alma.1` | `2.4.62-13.el9_8.9` | rpm（SQLite） | DEFAULT |
| Debian GNU/Linux 11 (bullseye) | `debian@sha256:6f519a81440354a85eb592c5f32109ab80605f6b892455983a6f618bf87fabe9` | `-` | `-` | `-` | `-` | dpkg | なし |
| Debian GNU/Linux 12 (bookworm) | `debian@sha256:268fb24c39bca92d326dd83ea3abebe4a3f7751c804ffef23bb6d857dd343ff8` | `3.0.22-1~deb12u2` | `9.2p1-2+deb12u10` | `1.22.1-9+deb12u10` | `2.4.68-1~deb12u1` | dpkg | なし |
| Debian GNU/Linux 13 (trixie) | `debian@sha256:9c6e381421d0f48d1b8133e573f33c185ee16cbf505eda9c4a8a4791b25ea8a6` | `3.5.7-1~deb13u3` | `10.0p1-7+deb13u4` | `1.26.3-3+deb13u10` | `2.4.69-1~deb13u1` | dpkg | なし |
| Rocky Linux 8.9 (Green Obsidian) | `rockylinux@sha256:9794037624aaa6212aeada1d28861ef5e0a935adaf93e4ef79837119f2a2d04c` | `1.1.1k-18.el8_10` | `8.0p1-34.el8_10` | `1.14.1-9.module+el8.4.0+542+81547229` | `2.4.37-65.module+el8.10.0+40402+af9563a3.13` | rpm（Berkeley DB） | DEFAULT |
| Rocky Linux 9.3 (Blue Onyx) | `rockylinux@sha256:d7be1c094cc5845ee815d4632fe377514ee6ebcf8efaed6892889657e5ddaaa6` | `3.5.8-2.el9_8` | `9.9p1-13.el9_8.rocky.0.1` | `1.20.1-28.el9_8.6.rocky.0.1` | `2.4.62-13.el9_8.9` | rpm（SQLite） | DEFAULT |
| Red Hat Enterprise Linux 10.3 (Coughlan) | `redhat/ubi10@sha256:1e9193f051ac70582821c8a941325c5053488c54c75cd0c31b577d871ac29dba` | `3.5.9-1.el10_3` | `9.9p1-33.el10_3` | `1.26.3-16.el10_3.1` | `2.4.63-13.el10_2.8` | rpm（SQLite） | DEFAULT |
| Red Hat Enterprise Linux 8.10 (Ootpa) | `redhat/ubi8@sha256:44f19e308462e9152cb26d641fc0ce5bf6cbdab3cd101367aed67573eb2cf20e` | `1.1.1k-18.el8_6` | `8.0p1-34.el8_10` | `1.14.1-9.module+el8.0.0+4108+af250afe` | `2.4.37-65.module+el8.10.0+25092+6f3ea0dd.13` | rpm（Berkeley DB） | DEFAULT |
| Red Hat Enterprise Linux 9.9 (Plow) | `redhat/ubi9@sha256:8b212f75a0e5a156ac28b1c5c030d2e8a07715254e19d522286118279399af81` | `3.5.9-1.el9_9` | `9.9p1-16.el9_9` | `1.20.1-32.el9_9.1` | `2.4.62-13.el9_8.9` | rpm（SQLite） | DEFAULT |
| Ubuntu 16.04.7 LTS | `ubuntu@sha256:1f1a2d56de1d604801a9671f301190704c25d604a416f59e03c04f5c6ffee0d6` | `1.0.2g-1ubuntu4.20` | `7.2p2-4ubuntu2.10` | `1.10.3-0ubuntu0.16.04.5` | `2.4.18-2ubuntu3.17` | dpkg | なし |
| Ubuntu 18.04.6 LTS | `ubuntu@sha256:152dc042452c496007f07ca9127571cb9c29697f42acbfad72324b2bb2e43c98` | `1.1.1-1ubuntu2.1~18.04.23` | `7.6p1-4ubuntu0.7` | `1.14.0-0ubuntu1.11` | `2.4.29-1ubuntu4.27` | dpkg | なし |
| Ubuntu 20.04.6 LTS | `ubuntu@sha256:8feb4d8ca5354def3d8fce243717141ce31e2c428701f6682bd2fafe15388214` | `1.1.1f-1ubuntu2.24` | `8.2p1-4ubuntu0.13` | `1.18.0-0ubuntu1.7` | `2.4.41-4ubuntu3.23` | dpkg | なし |
| Ubuntu 22.04.5 LTS | `ubuntu@sha256:74b12b11ffa550fba1929ad4d8d16533c34f6612728469671afba1b03b66881c` | `3.0.2-0ubuntu1.30` | `8.9p1-3ubuntu0.18` | `1.18.0-6ubuntu14.22` | `2.4.52-1ubuntu4.26` | dpkg | なし |
| Ubuntu 24.04.5 LTS | `ubuntu@sha256:2198e4c65076e9cb0b3d695219df667c0e3b0072da64ca3c2648aca17dcecaf5` | `3.0.13-0ubuntu3.16` | `9.6p1-3ubuntu13.20` | `1.24.0-2ubuntu7.19` | `2.4.58-1ubuntu8.18` | dpkg | なし |

この採取から分かること:

- パッケージ DB は、RHEL 8 系（RHEL 8.10、AlmaLinux 8.10、Rocky Linux 8.9）が Berkeley DB、RHEL 9 系と 10 系が SQLite。両方の読み取りが必要。
- システム全体の暗号ポリシーがあるのは RHEL 系だけで、採取したすべてで `DEFAULT`。Debian / Ubuntu にはない。
- 同じ RHEL 8 系でも、互換ディストリではパッケージのリリース文字列が異なる（例: nginx のモジュールストリームの識別子）。既定値表のキーはディストリを含める必要がある。
- Ubuntu は 16.04（OpenSSL 1.0.2g）、18.04 / 20.04（1.1.1 系）、22.04 / 24.04（3.0 系）で OpenSSL の系統が変わる。

### Windows Server 2022 / 2025 からの採取（2026-11-12、GitHub Actions）

`.github/workflows/windows-facts.yml`（`ci/windows-facts.ps1`）で採取した。
環境: Windows Server 2022 Datacenter 21H2（ビルド 20348.5773、ランナーイメージ `win22` 20261101.353.1）と Windows Server 2025。

**そのまま使える事実（形式に関するもの）**

- **証明書ストアの実体**: 証明書1件はレジストリの `...\SystemCertificates\<ストア>\Certificates\<SHA-1 指紋>` キーにあり、値は `Blob`（バイナリ）1つ。
  Blob は「プロパティ ID（4バイト）、予約（4バイト）、長さ（4バイト）、データ」の繰り返しで、採取した9件すべてを余りなく分解できた。
  プロパティ 32 が証明書本体（DER）で、その SHA-1 / SHA-256 は Windows 自身が報告した指紋と一致した。
- **秘密鍵の有無**: 秘密鍵を伴う証明書（テスト用に作成した3件）にはプロパティ 2（鍵の所在情報、188 バイト）があり、OS 配布のルート証明書にはない。Blob に秘密鍵そのものは含まれない。
- **ストアの置き場所**: `HKLM\SOFTWARE\Microsoft\SystemCertificates`（ROOT、CA、MY、AuthRoot、Disallowed、TrustedPublisher など）、`HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates`、
  `HKLM\SOFTWARE\Microsoft\EnterpriseCertificates`（NTAuth を含む）、`HKCU\SOFTWARE\Microsoft\SystemCertificates`。
  WOW6432Node 側には同じ内容が見える（件数が一致）。
- **ユーザーの個人ストアはファイル**: 実行ユーザーの `My` ストアに作った証明書は、レジストリではなく
  `%APPDATA%\Microsoft\SystemCertificates\My\Certificates\<指紋>` にファイルとして置かれた（形式はレジストリの Blob と同じ構造）。
- **HTTP.sys の SSL バインド**: `HKLM\SYSTEM\CurrentControlSet\Services\HTTP\Parameters\SslBindingInfo\<IP:ポート>` キーに、
  `SslCertHash`（証明書の SHA-1 指紋、バイナリ）、`SslCertStoreName`（文字列）、`AppId`（バイナリ）がある。`netsh http show sslcert` の表示と一致した。専用の解析は不要で、レジストリを読むだけでよい。
- **暗号スイートの順序**: ポリシーは `HKLM\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002` の `Functions`（カンマ区切りの文字列）、
  ローカル設定は `HKLM\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002` の `Functions`（複数行文字列）。曲線の順序は `EccCurves`（複数行文字列）。
- **その他**: FIPS は `...\Lsa\FipsAlgorithmPolicy` の `Enabled`。`.reg` の書き出しは UTF-16。最終アクセス時刻の更新は無効（`DisableLastAccess = 3`）。
  ユーザープロファイル直下には互換用のリパースポイント（`Application Data`、`My Documents` など）が多数ある。

**既定値としては使えないもの（ランナーイメージが調整済み）**

採取した環境は GitHub によって堅牢化されており、OS 本来の既定とは異なる。次の値をルールの既定値に使ってはならない。

- Schannel: `SSL 3.0` と `TLS 1.0` が Client / Server とも `Enabled=0`、RC4 が無効に設定されている。
- 暗号スイート: ポリシーで 10 個に絞られている（`TLS_AES_256_GCM_SHA384` から `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256` まで）。曲線もポリシーで `NistP384`、`NistP256` に絞られている。
- .NET Framework: `SchUseStrongCrypto` と `SystemDefaultTlsVersions` が 64bit / 32bit とも 1 に設定されている。

OS ビルド別の既定値は、Microsoft の公式文書を出典とし、調整されていない環境で確認できたものだけをルールに入れる。

**採取スクリプトの不具合（修正済み、再採取は未実施）**

- 暗号スイート一覧の JSON が空になっていた（表形式のテキストは取れている）。
- 証明書ストアごとの件数がすべて 0 になっていた（レジストリ配置の一覧では件数が取れている）。
- .NET 2.0 のレジストリ書き出しが数十 MB になっていた（必要な値だけを読む形に変更）。

---

## 2. OS とライブラリ

### 証明書ストアの実物確認（2026-11-12）

既定の起点で kagiya を各コンテナ内で動かした結果（出現数）:

| イメージ | `system-trust` の証明書 | `system-trust-java` | ストア外の証明書 | SSH ホスト鍵（秘密鍵 / 公開鍵） |
|---|---|---|---|---|
| RHEL 8.10（`redhat/ubi8@sha256:44f19e30…`） | 904 | 証明書 118、キーストア 1（JKS） | 6（`/etc/rhsm/ca`、`/etc/pki/product-default` など製品・サブスクリプション用） | 4 / 4 |
| RHEL 9.9（`redhat/ubi9@sha256:8b212f75…`） | 1022 | 証明書 118、キーストア 1 | 8（上記に加え `/etc/keys/ima`） | 3 / 3 |
| Ubuntu 16.04.7（`ubuntu@sha256:1f1a2d56…`） | 258 | なし | 0 | 4 / 4 |

- 解析エラーは 0 件。スキップは出力先・ログ先の自動除外と、存在しない起点だけだった。
- Ubuntu 16.04（OpenSSH 7.2p2）の `ssh-keygen -A` は DSA 1024 ビットのホスト鍵も生成し、秘密鍵は従来の PEM 形式（PKCS#1 / SEC1 / DSA）で書かれる。RHEL 8.10（OpenSSH 8.0p1）も DSA のホスト鍵を生成する。RHEL 9.9（OpenSSH 9.9p1）は生成しない。

### Phase 1b に向けて実物から採取した事実（2026-11-12）

各イメージに `openssl`、`ca-certificates`、`openssh-server`、`nginx`、Apache httpd を導入して採取した。

| 項目 | RHEL 8.10（UBI 8） | RHEL 9.9（UBI 9） | Ubuntu 16.04.7 | Ubuntu 24.04.5 |
|---|---|---|---|---|
| OpenSSL | `openssl-1.1.1k`（`OpenSSL 1.1.1k  FIPS 25 Mar 2021`） | `openssl-3.5.9-1.el9_9` | `1.0.2g-1ubuntu4.20` | `3.0.13-0ubuntu3.16` |
| OpenSSH | `OpenSSH_8.0p1` | `openssh-9.9p1-16.el9_9` | `1:7.2p2-4ubuntu2.10` | `1:9.6p1-3ubuntu13.20` |
| nginx | `1:1.14.1-9.module+el8.0.0+4108+af250afe` | `2:1.20.1-32.el9_9.1` | `1.10.3-0ubuntu0.16.04.5` | `1.24.0-2ubuntu7.19` |
| Apache httpd | `2.4.37-65.module+el8.10.0+25092+6f3ea0dd.13` | `2.4.62-13.el9_8.9` | `2.4.18-2ubuntu3.17` | `2.4.58-1ubuntu8.18` |
| パッケージ DB | rpm、Berkeley DB（`/var/lib/rpm/Packages`、Hash version 9） | rpm、SQLite（`/var/lib/rpm/rpmdb.sqlite`） | dpkg（`/var/lib/dpkg/status`） | dpkg |
| OpenSSL の設定ディレクトリ | `/etc/pki/tls` | `/etc/pki/tls` | `/usr/lib/ssl` | `/usr/lib/ssl` |
| システム全体の暗号ポリシー | あり（`DEFAULT`）。`crypto-policies-20230731-1.git3177e06.el8` | あり（`DEFAULT`）。`crypto-policies-20260714-1.git65b74f7.el9` | なし | なし |

sshd と暗号ポリシーの結び付き方（設計書 5.4 の「順序が逆転する例」の実物）:

- **RHEL 8.10**: systemd ユニットが `EnvironmentFile=-/etc/crypto-policies/back-ends/opensshserver.config` を読み、`ExecStart=/usr/sbin/sshd -D $OPTIONS $CRYPTO_POLICY` で起動する。
  `opensshserver.config` の中身は `CRYPTO_POLICY='-oCiphers=... -oMACs=... '` という**コマンドライン引数**で、`sshd_config` の記載より優先される。`/etc/sysconfig/sshd` に `# CRYPTO_POLICY=` というコメント行があり、これを有効にするとポリシーから外れる。
- **RHEL 9.9**: ユニットは `ExecStart=/usr/sbin/sshd -D $OPTIONS` で、ポリシーを引数では渡さない。`/etc/ssh/sshd_config` が `Include /etc/ssh/sshd_config.d/*.conf` を持ち、`50-redhat.conf` が `Include /etc/crypto-policies/back-ends/opensshserver.config` を持つ。
  `opensshserver.config` の中身は `Ciphers ...`、`MACs ...`、`KexAlgorithms ...`、`RequiredRSASize 2048` などの**設定ファイル形式**。
- **Ubuntu 16.04 / 24.04**: 暗号ポリシーの仕組みはない。ユニットは `ExecStart=/usr/sbin/sshd -D $SSHD_OPTS`（`EnvironmentFile=-/etc/default/ssh`）。24.04 の `sshd_config` は `Include /etc/ssh/sshd_config.d/*.conf` を持つ。

バイナリから分かること（RHEL 8.10 の `/usr/sbin/sshd`）:

- `DT_NEEDED` に `libcrypto.so.1.1` があり、`/lib64/libcrypto.so.1.1` に解決される。
- バイナリ内の文字列を `OpenSSH_[0-9]...` のような緩いパターンで探すと、互換性判定用の文字列（`OpenSSH_2`、`OpenSSH_3.0` など）が多数当たる。版の特定には `OpenSSH_<数字>.<数字>p<数字>` の形に絞る必要がある。

### リンクしている暗号ライブラリの特定の実物確認（2026-11-12、検証ラボ、arm64）

各コンテナに OpenSSL・OpenSSH・nginx・Apache httpd を導入し、kagiya の結果を `ldd` と各アプリの版表示（`sshd -V`、`nginx -v`、`httpd -v`、`openssl version`）と突き合わせた。

| イメージ | リンク（kagiya / ldd） | 不一致 | アプリ・ライブラリの版 |
|---|---|---|---|
| RHEL 8.10（`redhat/ubi8@sha256:44f19e30…`） | 5 / 5 | 0 | sshd 8.0p1、nginx 1.14.1、httpd 2.4.37、OpenSSL 1.1.1k（すべて一致） |
| RHEL 9.9（`redhat/ubi9@sha256:8b212f75…`） | 5 / 5 | 0 | sshd 9.9p1、nginx 1.20.1、httpd 2.4.62、OpenSSL 3.5.9（すべて一致） |
| Ubuntu 16.04.7（`ubuntu@sha256:1f1a2d56…`） | 5 / 5 | 0 | sshd 7.2p2、nginx 1.10.3、apache2 2.4.18、OpenSSL 1.0.2g（すべて一致） |
| Ubuntu 24.04.5（`ubuntu@sha256:2198e4c6…`） | 5 / 5 | 0 | sshd 9.6p1、nginx 1.24.0、apache2 2.4.58、OpenSSL 3.0.13（すべて一致） |

ELF の読み取りは実物のバイナリ 30 個で `readelf -d` の出力と一致し、`/etc/ld.so.cache` の読み取りは RHEL 9.9 と Ubuntu 16.04 で `ldconfig -p` の出力と一致した。

実物で分かったこと:

- **アプリのバイナリに埋め込まれた OpenSSL の版は、実行時に使われる版とは限らない。** RHEL 8.10 の nginx には `OpenSSL 1.1.1 FIPS  11 Sep 2018`（ビルド時の版）が入っているが、実際にリンクされるのは 1.1.1k。RHEL 9.9 の `mod_ssl.so` には 3.5.8 が入っているが、ライブラリは 3.5.9。版はライブラリ本体から読む必要がある。
- **Apache httpd の本体は暗号ライブラリにリンクしていない。** TLS を担うのは実行時に読み込まれる `mod_ssl.so` で、こちらが libssl / libcrypto にリンクしている。アプリの定義でモジュールの場所を持つ必要がある。
- **OpenSSL 3 系の libssl には版文字列がない**（libcrypto にだけある）。libssl の版は「不明」とし、パッケージの版で補う。
- **Ubuntu 16.04 の `/etc/ld.so.cache` は旧形式（`ld.so-1.7.0`）で始まり、その後ろに新形式が続く。**
- **共有ライブラリはシンボリックリンク経由で参照される**（`libcrypto.so.3` → `libcrypto.so.3.5.9`、`/lib64` → `usr/lib64`）。リンクは OS に一括で解決させず、1段ずつ、その都度マウント表で判定しながら辿る。

限界:

- 環境変数 `LD_LIBRARY_PATH` や `LD_PRELOAD` による差し替えは分からない（稼働中プロセスの環境は調べない方針のため）。
- コンポーネントとパッケージの対応は、名前による推定（ルールに書いたパッケージ名のうち、導入済みの最初のもの）。同じライブラリの複数の版が導入されている場合は、対応を誤る可能性がある。
- 確認は arm64 のコンテナ。amd64 では未確認（ライブラリの置き場所は `/lib/x86_64-linux-gnu` などに変わるが、キャッシュ経由で解決されるはず）。

### OS 暗号設定の実物確認（2026-11-12、検証ラボ、arm64）

各コンテナで kagiya を動かし、結果を実物の設定ファイルと OS のコマンドの報告に突き合わせた。

| イメージ | 暗号ポリシー（kagiya / `update-crypto-policies --show`） | OpenSSL の設定ファイル | システム既定の TLS 設定 |
|---|---|---|---|
| RHEL 8.10（`redhat/ubi8@sha256:44f19e30…`） | DEFAULT / DEFAULT | `/etc/pki/tls/openssl.cnf` | 7 項目。暗号ポリシーが生成したファイルの内容と全項目一致 |
| RHEL 9.9（`redhat/ubi9@sha256:8b212f75…`） | DEFAULT / DEFAULT | `/etc/pki/tls/openssl.cnf` | 8 項目（`Groups` が加わる）。全項目一致 |
| Ubuntu 16.04.7（`ubuntu@sha256:1f1a2d56…`） | なし / コマンドなし | `/etc/ssl/openssl.cnf` | 設定されていない |
| Ubuntu 24.04.5（`ubuntu@sha256:2198e4c6…`） | なし / コマンドなし | `/etc/ssl/openssl.cnf` | 設定されていない |

実物で分かったこと:

- **RHEL の OpenSSL は、設定ファイルの連鎖で暗号ポリシーを取り込む。** `openssl.cnf` の `openssl_conf` → `ssl_conf` → `system_default` と辿った先の節が、
  `/etc/crypto-policies/back-ends/opensslcnf.config` を `.include` している。このファイルは `/usr/share/crypto-policies/DEFAULT/opensslcnf.txt` へのシンボリックリンク。
- **`.include` の書き方が版で違う。** RHEL 8.10 は `.include /path`、RHEL 9.9 は `.include = /path`。RHEL 9.9 にはディレクトリの取り込み（`.include /etc/pki/tls/openssl.d`）もある。
- **RHEL 8.10 と 9.9 の DEFAULT ポリシーの内容**: `TLS.MinProtocol = TLSv1.2`、`TLS.MaxProtocol = TLSv1.3`、暗号の指定は `@SECLEVEL=2` で始まる。
  署名アルゴリズムの一覧の末尾には、RHEL 8.10 では `ECDSA+SHA1:RSA+SHA1`（SHA-1 による署名）が含まれている。
- **Ubuntu の `openssl.cnf` には、システム既定の TLS 設定を読み込む経路がない**（16.04 は `openssl_conf` 自体がなく、24.04 はプロバイダの設定だけ）。Ubuntu での既定値は、OpenSSL のビルド時の設定で決まる。
- **RHEL 8.10 の `opensslcnf.config` は末尾に改行がない。** 確認用スクリプトがこれで次の行とつながり、一時的に「不一致」と表示された（kagiya の読み取りは正しかった）。
- **コンテナ内には `/proc/sys/crypto/fips_enabled` がなかった。** FIPS モードの読み取りは実物では未確認。

---

## 3. OpenSSH（sshd）

### sshd の設定値の実物確認（2026-11-12、検証ラボ、arm64）

各コンテナで、kagiya が「有効」と判定した設定値を、同じ環境の sshd 自身が報告した実効値（`sshd -T`。RHEL 8.10 は systemd と同じ起動引数を付けて実行）と突き合わせた。

| イメージ | サービスの有効化 | 突き合わせた項目 | 不一致 |
|---|---|---|---|
| RHEL 8.10（`redhat/ubi8@sha256:44f19e30…`） | 有効（`multi-user.target.wants/sshd.service`） | Ciphers、MACs、KexAlgorithms、GSSAPIKexAlgorithms、HostKeyAlgorithms、CASignatureAlgorithms（いずれも起動引数で渡るポリシー）、HostKey | 0 |
| RHEL 9.9（`redhat/ubi9@sha256:8b212f75…`） | 有効（同上） | 上記6項目と RequiredRSASize（設定ファイルとして取り込まれるポリシー）、HostKey（既定） | 0 |
| Ubuntu 16.04.7（`ubuntu@sha256:1f1a2d56…`） | 有効（`multi-user.target.wants/ssh.service`） | HostKey（4つ明記。DSA を含む） | 0 |
| Ubuntu 24.04.5（`ubuntu@sha256:2198e4c6…`） | 有効（`sockets.target.wants/ssh.socket`。サービスではなくソケットで起動する） | HostKey（既定） | 0 |

設定から参照されているホスト鍵（秘密鍵）には、4環境とも「有効」が付いた。RHEL 8.10 では、ホスト鍵の一括生成で作られた DSA の鍵が設定から参照されておらず、「不明」となった（使われていない鍵の実例）。

分かったこと・決めたこと:

- **RHEL 8.10 では、`sshd_config` に Ciphers などを書いても効かない。** ポリシーが起動引数（`-oCiphers=...`）として渡され、sshd は「同じ項目は最初に得た値を使う」ため。kagiya は両方を記録し、設定ファイル側を「効いていない」と示す。`/etc/sysconfig/sshd` で `CRYPTO_POLICY=` と空にするとポリシーから外れる（実物のコメントにある手順）ことも反映した。
- **Ubuntu 24.04 の sshd はソケット起動。** 有効化のリンクは `ssh.service` ではなく `ssh.socket` にある。待ち受けるポートもソケットのユニット側に書かれている。
- **Ubuntu 16.04 には、互換用の別名 `/etc/systemd/system/sshd.service`（`ssh.service` へのリンク）がある。**
- 設定に書かれた SSH のアルゴリズム名は、現時点では文字列として記録するだけで、暗号カタログの資産とは結び付けていない。

---

## 4. Web サーバーと OpenSSL

### nginx・Apache httpd の設定値の実物確認（2026-11-12、検証ラボ、arm64）

各コンテナで「導入しただけの状態」と「TLS を有効にした状態」の2通りを作り、kagiya が記録した設定値を実物と突き合わせた。
nginx の正解は `nginx -T`（取り込みを展開した設定の全文）、Apache の正解は `-t -D DUMP_INCLUDES` が報告した取り込み済みファイルの内容。

| イメージ | 場面 | nginx（kagiya / 正解） | Apache（kagiya / 正解） | サービスの有効化（nginx / Apache） |
|---|---|---|---|---|
| RHEL 8.10 | 導入のみ | 0 / 0 | 6 / 6 | 導入のみ / 導入のみ |
| RHEL 8.10 | TLS 有効 | 8 / 8 | 6 / 6 | 同上 |
| RHEL 9.9 | 導入のみ | 0 / 0 | 6 / 6 | 導入のみ / 導入のみ |
| RHEL 9.9 | TLS 有効 | 8 / 8 | 6 / 6 | 同上 |
| Ubuntu 16.04.7 | 導入のみ | 2 / 2 | 0 / 0 | 有効 / 導入のみ |
| Ubuntu 16.04.7 | TLS 有効 | 10 / 10 | 5 /（照合手段なし） | 同上 |
| Ubuntu 24.04.5 | 導入のみ | 2 / 2 | 0 / 0 | 有効 / 有効 |
| Ubuntu 24.04.5 | TLS 有効 | 10 / 10 | 5 / 5 | 同上 |

照合できた範囲では、項目・値とも全件一致した（イメージのダイジェストは他の実物確認と同じ）。

分かったこと:

- **RHEL 系の Apache は、導入しただけで TLS の設定が有効になっている**（`conf.d/ssl.conf` が取り込まれ、`SSLEngine on`、`SSLCipherSuite PROFILE=SYSTEM`）。一方、サービスは有効化されていない。
- **Debian / Ubuntu の Apache は、導入しただけでは TLS が無効**。TLS のモジュールもサイトも `mods-enabled/`・`sites-enabled/` へのリンクで有効にする方式で、リンクがなければ設定ファイルが存在しても取り込まれない。ポート 443 の待ち受けも `<IfModule ssl_module>` の中にある。
- **Ubuntu の nginx は、導入しただけで `ssl_protocols TLSv1 TLSv1.1 TLSv1.2 ...` が http 全体に書かれている**（16.04 は TLSv1.2 まで、24.04 は TLSv1.3 まで）。RHEL 系の既定の設定には TLS の記載がない。
- **パッケージを導入したときにサービスが有効化されるかは、ディストリで違う**。RHEL 系は nginx も httpd も有効化されず、Ubuntu は nginx が有効化される。「入っているだけ」と「起動するよう設定されている」の区別が、実物でも分かれることを確認した。
- 照合の正解側の制約: RHEL 8.10 の「導入のみ」では、証明書ファイルがまだ無いため `httpd -M` 自体が失敗する（kagiya は設定ファイルからモジュールの読み込みを読むので影響を受けない）。Ubuntu 16.04 の Apache 2.4.18 は `DUMP_INCLUDES` に対応しておらず、取り込み済みファイルの一覧が得られなかった（`-S` と `-M` の表示とは整合）。

これで Phase 1b（Linux の事実収集）の項目は一通り実装した。記録しているのは「設定に明記された値」までで、記載のない項目の既定値の解決（実効値）は Phase 1c で行う。

### OpenSSL の暗号文字列の展開と、nginx・Apache の暗号スイートの実効値（2026-11-12、検証ラボ、arm64）

**構成（共通部品と、アプリ・版ごとの事情の分離）**

| 層 | 置き場所 | 内容 |
|---|---|---|
| 展開の手順 | `internal/tlsciphers` | どの版にも共通。OpenSSL の規則（追加、`+` 並べ替え、`-` 削除、`!` 永久に除外、`@STRENGTH`、`@SECLEVEL`）の適用 |
| サーバーの実効スイート | `internal/tlseffective` | どのアプリにも共通。展開結果を、レベル・証明書の種類・DH パラメータで絞り込む |
| アプリごとの設定の意味 | `internal/collect/apps/nginx.go`、`apache.go`、`sshd.go` | どの記載がどの範囲に効くか（引き継ぎ、上書き、後勝ち）だけを扱う |
| 版・ディストリで変わる値 | `rules/ciphers/`、`rules/defaults/` | すべてデータ（出典付き）。Go のコードに、版やディストリによる分岐は置かない |

**対応表の採取**: 8 つのパッケージ版で、空の openssl.cnf を読ませた `openssl ciphers -V` に、全スイートの属性、語ごとの該当スイート（94 語）、
`@STRENGTH` の並べ替え結果、セキュリティレベルごとに使えるスイート、TLS 1.3 のスイートを報告させた。
中身が同じ版（RHEL 9.9 と 10.3）は 1 つの表にまとめている。

**展開の突き合わせ**: よく使われる書き方と、規則の境界を突く書き方の計 39 種類の暗号文字列を、各版の openssl 自身に展開させ、kagiya の展開結果と比べた。
8 版 × 39 種類 = 312 件すべてが、スイートの集合・並びとも一致した（`internal/tlsciphers/testdata/corpus.tsv`。単体テストで毎回確かめる）。

**サーバーでの突き合わせ（差分テスト）**: 各イメージに nginx と Apache httpd を導入して実際に起動し、同じコンテナ内から、スイート 1 つずつ・プロトコル 1 つずつのハンドシェイク
（`openssl s_client`）で「受け入れるスイート」を数え上げた。同じ状態で kagiya を実行し、求めた実効値と比べた。

| 場面 | 設定 |
|---|---|
| 既定 | 証明書だけを指定（暗号・プロトコルは書かない） |
| 引き継ぎ | 全体（nginx は http、Apache は VirtualHost の外）に暗号文字列を書き、server / VirtualHost には書かない |
| 書き換え | 上と同じ構成で、別の server / VirtualHost に別の暗号文字列（nginx は `ssl_dhparam` も）を書く |
| 暗号ポリシー | `PROFILE=SYSTEM`（RHEL 系のみ） |

| イメージ | OpenSSL | nginx | Apache httpd | 一致 |
|---|---|---|---|---|
| RHEL 8.10 | openssl-libs 1.1.1k-18.el8_6 | 1.14.1 | 2.4.37 | 8 / 8 |
| RHEL 9.9 | 3.5.9-1.el9_9 | 1.20.1 | 2.4.62 | 8 / 8 |
| RHEL 10.3 | 3.5.9-1.el10_3 | 1.26.3 | 2.4.63 | 8 / 8 |
| Ubuntu 16.04.7 | libssl1.0.0 1.0.2g-1ubuntu4.20 | 1.10.3 | 2.4.18 | 6 / 6 |
| Ubuntu 20.04.6 | libssl1.1 1.1.1f-1ubuntu2.24 | 1.18.0 | 2.4.41 | 6 / 6 |
| Ubuntu 22.04.5 | libssl3 3.0.2-0ubuntu1.30 | 1.18.0 | 2.4.52 | 6 / 6 |
| Ubuntu 24.04.5 | libssl3t64 3.0.13-0ubuntu3.16 | 1.24.0 | 2.4.58 | 6 / 6 |
| Debian 13 | libssl3t64 3.5.7-1~deb13u3 | 1.26.3 | 2.4.69 | 6 / 6 |

合計 54 場面すべてで、kagiya が求めた TLS 1.2 以下のスイートの集合が、実際にサーバーが受け入れた集合と一致した。
TLS 1.3 が有効だった場面では、TLS 1.3 のスイートの集合も一致した。確かめたのは集合の一致までで、優先順は測っていない。
イメージのダイジェストとパッケージ版は、`rules/ciphers/openssl.yaml` と `rules/defaults/` に記載している。

分かったこと:

- **暗号文字列だけでは、実際に使えるスイートは決まらない。** 同じ `HIGH:!aNULL:!MD5` でも、RHEL 9.9 の nginx が受け入れるのは 115 個の展開結果のうち 38 個。
  セキュリティレベル（暗号ポリシー由来の 2）、証明書の種類（DSA の証明書はない）、DH パラメータ（nginx は `ssl_dhparam` がなければ DHE を使わない）で絞られる。
- **nginx は版によって DHE の扱いが違う。** Ubuntu 16.04 の 1.10.3 は組み込みの DH パラメータで DHE を受け入れ、それ以降の版は `ssl_dhparam` の指定がなければ受け入れない。
  Apache は、測った 8 版すべてで、指定がなくても DHE を受け入れた。
- **RHEL の Apache の既定の VirtualHost 以外は、暗号ポリシーに従わない。** パッケージの設定は `_default_:443` の VirtualHost の中にだけ `SSLCipherSuite PROFILE=SYSTEM` を書いている。
  自分で足した VirtualHost に暗号の記載がなければ、mod_ssl の既定（`DEFAULT`）になり、暗号ポリシーとは別の集合になる（RHEL 9.9 で 27 個と 31 個）。
- **`PROFILE=SYSTEM` が読むファイルは RHEL の版で違う。** RHEL 8 は `/etc/crypto-policies/back-ends/openssl.config`、RHEL 9・10 は `opensslcnf.config` の `CipherString` の行。
  RHEL 10 には前者のファイルがない。どちらを読むかは、libssl に埋め込まれたパスから確かめ、対応表に持たせた。
- **表示される鍵長と、並べ替えに使われる強度は違うことがある。** 3DES（表示 168）と、OpenSSL 3.5 の CCM8（表示 128 / 256）は、`@STRENGTH` で 128 ビットのスイートより後ろに並ぶ。
  対応表の強度は、実物の並べ替え結果を再現する値を持たせている。
- **標準名（`TLS_ECDHE_RSA_WITH_...`）を暗号文字列に書けるのは OpenSSL 3.5 だけ。** 1.1.1 と 3.0 では、知らない語として無視される。
- **RHEL 8・9 の DEFAULT ポリシーは鍵交換に RSA を許し、RHEL 10 は許さない。** 同じ `PROFILE=SYSTEM` で、nginx が受け入れるスイートは RHEL 9.9 の 22 個に対し、RHEL 10.3 は 14 個。
- **訂正（2026-11-12）: 「RHEL 9・10 の OpenSSL はレベル 0 でも TLS 1.0 / 1.1 を受け入れない」としていたのは誤り。**
  ライブラリ単体の測定で、サーバーに ECDSA の証明書だけを持たせていたために、そう見えていた。TLS 1.0 / 1.1 での ECDSA の署名は SHA-1 を使い、RHEL 9 では拒否される。
  RSA の証明書を持つ nginx に `ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3` と `ssl_ciphers ALL:@SECLEVEL=0` を設定すると、RHEL 9.9 でも TLS 1.0 / 1.1 を受け入れた（各 6 スイート）。
  どのプロトコルが通るかは、ライブラリの版・セキュリティレベル・証明書の種類・スイートの組み合わせで決まり、プロトコル単位の表では表せない。
  この測定に基づく値（対応表の `protocols`）は、どの機能にも使われる前に対応表から取り除いた。
- **nginx の `ssl_protocols` は、同じ階層に 2 回書くと、警告を出したうえで両方を合わせた値になる。** Ubuntu の `nginx.conf` は http に `ssl_protocols` を書いているので、
  `conf.d` に別の値を足しても置き換わらない。プロトコルの実効値の解決で扱う。

測定の方針（2026-11-12）: 基準になるデータは、数を増やすことよりも、既定や解釈が変わる境目（OpenSSL 1.0.2 → 1.1.1 → 3.0 → 3.5、ディストリの系列）の前後を測ることを優先する。
間の版は、同じ系列・同じ上流版に限って補間し、結果に補間であることを残して確度を一段下げる。測定は自動化（定期実行）せず、必要なときに手動で採取する（2026-11-12 決定）。補間は、sshd・nginx・Apache の既定値表と OpenSSL の対応表のすべてに同じ条件で適用する。

### 受け入れる鍵交換のグループの実効値（2026-11-12、検証ラボ、arm64）

サーバーが耐量子のハイブリッド鍵交換（X25519MLKEM768 など）を受け入れる設定になっているかを、結果とレポートで分かるようにした。
項目は `tls.groups`。nginx・Apache httpd・HAProxy・stunnel の、待ち受けの範囲ごとに求める。

決まり方（上にあるものが優先）:

1. アプリの設定: nginx `ssl_ecdh_curve`（`auto` は指定なしと同じ）、Apache `SSLOpenSSLConfCmd Groups` / `Curves`（全体、VirtualHost の順に適用され、後のものが効く）、
   HAProxy `bind` の `curves`、なければ全体の `ssl-default-bind-curves`、stunnel `curves`（サービスの節、なければ全体）
2. アプリ自身の既定（stunnel だけが持つ。`X25519:P-256:X448:P-521:P-384`。`rules/defaults/stunnel.yaml`）
3. システムの openssl.cnf の `Groups`（RHEL 系では暗号ポリシーが生成する）
4. ライブラリの既定

そのうえで、適用されるセキュリティレベルで使えないグループを落とす。指定の解釈（`internal/tlsgroups`）、知っている名前と別名、既定、レベルごとに使えるグループは、
パッケージ版ごとに実測した対応表（`rules/groups/openssl.yaml`、6 表・7 版）から引く。表にない版の扱い（リリースだけ違えば補間、確度を一段下げる）は暗号スイートと同じ。

実物で分かったこと:

- **指定の書き方は、OpenSSL の版で違う。** 1.1.1 と 3.0 は「:」区切りだけで、名前は大文字小文字を区別し、同じグループを2回書くと拒否する。
  3.5 は「/」、接頭辞「?」（知らない名前なら無視）「*」（鍵共有を先に送る印）「-」（取り除く）、`DEFAULT`、大文字小文字を区別しない名前を受け付ける。
  参照実装と実物の突き合わせは 247 件すべて一致。
- **OpenSSL 3.5 の既定には X25519MLKEM768 が入っている。** Debian 13（3.5.7）の nginx・Apache・HAProxy は、何も設定しなくてもハイブリッドを受け入れる。
- **RHEL 9.9 は、OpenSSL 3.5 でもハイブリッドを受け入れない。** 暗号ポリシーの `Groups` が従来のグループだけを並べていて、ライブラリの既定を上書きするため。
  RHEL 10.3 のポリシーは、ハイブリッド 3 種（X25519MLKEM768、SecP256r1MLKEM768、SecP384r1MLKEM1024）を先頭に並べている。
- **stunnel は、どのディストリでもハイブリッドを受け入れない。** 自身の既定のグループを必ず設定し、システムの設定にもライブラリの既定にも従わない。
- **HAProxy 1.8 / 2.0 は、全体の `ssl-default-bind-curves` を受け付けない**（起動に失敗する）。`bind` の行の `curves` は受け付ける。

差分テスト: 7 ディストリ（RHEL 8.10 / 9.9 / 10.3、Ubuntu 20.04 / 22.04 / 24.04、Debian 13）× 4 アプリ × 場面（指定なし、全体の指定の引き継ぎ、内側での書き換え）の
94 の待ち受けすべてで、kagiya の実効値と、グループを 1 つずつ指定したハンドシェイクで実際に受け入れたグループが一致した（`lab/phase1e/appgroups.sh`、`appgroups-summary.py`）。

差分テストで見つかった不具合: RHEL 10.3 の 4 件で、kagiya がシステムの `Groups` を使わず、ライブラリの既定を確度「高」で答えていた。
OS 設定の収集が値の文字種を絞っており、「?」「/」を含む RHEL 10 の `Groups` を不正な値として落としていたため。単体テストは OS 設定を直接与えていたので通っていた。
文字種に「?」「/」を足したうえで、**値を記録しなかった項目には印（`openssl.system_default.unread`）を残し、暗号スイートとグループの解決は、
それを「指定なし」とは扱わず「不明」にする**ようにした（同じ種類の誤りが、別の値で再び起きても、誤った結果を高い確度で出さないため）。

評価: グループの名前を、ポリシーの `tls-group` の規則で判定する。従来の ECDH / DH は「量子計算機に弱い」（鍵共有なので、いま記録された通信が将来解読され得る）、
ML-KEM との組み合わせは「ハイブリッド」、ML-KEM 単独は「耐量子」。ffdhe2048 と P-224 は強度 112 ビットで「非推奨」。対応表にあるグループはすべて判定できる（テストで確かめている）。

---

## 5. OpenSSL を使うアプリ（HAProxy、stunnel、Postfix、PostgreSQL、Dovecot、MariaDB / MySQL）

### 対応アプリの拡大: OpenSSL を使う A ランクのアプリ（2026-11-12〜、検証ラボ、arm64）

調査資料の A ランク 41 件のうち、OpenSSL を使うアプリから順に対応する。暗号文字列の展開（`internal/tlsciphers`）と、サーバーの実効スイートの計算
（`internal/tlseffective`、`internal/collect/apps/tlsserver.go`）はそのまま共有し、アプリごとに足すのは次の3点だけにする。

1. 設定ファイルの文法（`internal/parse/<アプリ>conf`）
2. どの記載がどの範囲に効くか（`internal/collect/apps/<アプリ>.go`）
3. 版ごとの既定と挙動の実測（`rules/defaults/<アプリ>.yaml`、出典付き）

UBI のリポジトリの範囲で導入できる OpenSSL 系の A ランクは、HAProxy、stunnel、Postfix の3つだった（RHEL 8.10 / 9.9 / 10.3 とも同じ）。
PostgreSQL、Dovecot、BIND、OpenVPN、MariaDB / MySQL、OpenDKIM、OpenLDAP は UBI にはなく、Debian・Ubuntu にはある。

| アプリ | 状態 | 差分テスト |
|---|---|---|
| HAProxy | 済 | 8 ディストリ × 7 場面（1.6 は 5 場面）の 54 場面すべてで、kagiya の実効値と実際に受け入れたスイートが一致 |
| stunnel | 済 | 8 ディストリの 49 場面すべてで一致（Ubuntu 16.04 の版は TLS 1.3 の指定を受け付けないので、その場面はない） |
| Postfix（受信側の smtpd） | 済 | 8 ディストリ × 12 場面の 96 の待ち受けすべてで、暗号スイート・TLS 1.3 のスイート・鍵交換のグループが実測と一致（グループは、対応表のない OpenSSL 1.0.2 の 12 件を除く） |
| PostgreSQL | 済 | 7 ディストリ（AlmaLinux 8 / 9 / 10、Ubuntu 20.04 / 22.04 / 24.04、Debian 13。PostgreSQL 10〜17）の 55 場面すべてで一致 |
| Dovecot | 済 | 8 ディストリ（AlmaLinux 8 / 9 / 10、Ubuntu 16.04〜24.04、Debian 13。Dovecot 2.2.22〜2.4.1）の 81 の待ち受けすべてで一致（グループは、対応表のない OpenSSL 1.0.2 の 6 件を除く） |
| MariaDB | 済 | 6 版（AlmaLinux 8 / 9 / 10、Ubuntu 22.04 / 24.04、Debian 13。10.3〜11.8）の 41 場面すべてで一致。Ubuntu 16.04（OpenSSL なしのビルド）と 20.04（鍵を読めず起動しない）は測れていない |
| MySQL | 済 | 6 版（AlmaLinux 8 / 9 / 10、Ubuntu 20.04 / 22.04 / 24.04。8.0、8.4）の 45 場面すべてで一致。Ubuntu 16.04（5.7）は、内蔵の既定を特定できず表に入れていない |
| Java（JDK の層） | 済 | 導入されている OpenJDK ごとの TLS の既定（下記）。Tomcat、Spring Boot、WildFly は未 |
| Tomcat などの Java のサーバー、OpenSSH クライアント、rsyslog、Zabbix、VPN、認証基盤、鍵ファイルだけのもの | 未 | 2026-11-13 に優先順位を見直した（下記） |
| 　 | 　 | RHEL 系は AlmaLinux の公式イメージで測る（2026-11-12 に決定） |

HAProxy の測定: 各イメージの haproxy を実際に起動し、サーバー名を付けたハンドシェイクで受け入れるスイートを数え上げた。
場面は、暗号の指定なし、全体の指定（`ssl-default-bind-ciphers`）の引き継ぎと `bind` の行での書き換え、パッケージの設定ファイルが全体に書いている値、
TLS 1.3 のスイートの指定（`ssl-default-bind-ciphersuites`、`bind` の `ciphersuites`）。

HAProxy で分かったこと:

- **暗号の指定が何もなければ、HAProxy は何も設定せず、OpenSSL のシステム既定のままになる。** RHEL では暗号ポリシーの暗号文字列、それ以外ではライブラリの `DEFAULT` と一致した。
  nginx（`HIGH:!aNULL:!MD5` を必ず設定する）とは決まり方が違う。既定の表では、この扱いを `@system` と表している。
- **DH パラメータの指定がないときに DHE を使えるかは、版による。** 1.6.3、1.8.27、2.0.33、2.4.30 は組み込みのパラメータで受け入れ、2.8.14、2.8.30、3.0.5、3.0.11 は受け入れない。
  Ubuntu 24.04 と Debian 13 のパッケージの設定は DHE のスイートを列挙しているが、DH パラメータの指定がないため、実際には受け入れない。
- **サーバー名（SNI）のない接続には、最初の証明書だけが使われる。** RSA と ECDSA の証明書を両方指定しても、サーバー名なしでは RSA のスイートしか通らなかった。
  kagiya の実効値は「どの証明書も選ばれ得る」前提の集合（サーバー名を付けて測った集合と一致）。
- **古い版（1.6.3）は、同じ名前の証明書を複数指定しても最初の1つしか使わない。**
- **RHEL 系のユニットは `/etc/haproxy/conf.d` も読ませる。** Debian・Ubuntu のユニットは主の設定ファイルだけ。kagiya は、ユニットの起動コマンドの `-f` に従って読むファイルを決める。

stunnel で分かったこと:

- **既定の暗号文字列は、版ごとにバイナリに埋め込まれていて、ディストリで違う。** RHEL 8.10 / 9.9 / 10.3 は `PROFILE=SYSTEM`、Ubuntu 20.04 以降と Debian 13 は
  `HIGH:!aNULL:!SSLv2:!DH:!kDHEPSK`（DH を含まない）、Ubuntu 16.04（5.30）は埋め込みがなく OpenSSL の既定のまま。
- **TLS 1.3 のスイートは、stunnel 自身の既定がシステムの設定より優先される。** RHEL の暗号ポリシーは 4 個を指定しているが、stunnel が受け入れるのは自身の既定の 3 個。
  nginx・Apache・HAProxy（システムの設定に従う）とは決まり方が違う。既定の表に `tls.ciphersuites-tls13` として持たせた。
- **設定は `/etc/stunnel/*.conf` のそれぞれが 1 つの起動単位。** Debian 系では名前が決まっていない。ルールの設定ファイルの候補にパターンを書けるようにした。
- **どの版も、組み込みの DH パラメータで DHE を受け入れる。**

Postfix の測定（2026-11-13）: 各イメージの postfix を実際に起動し、STARTTLS（`openssl s_client -starttls smtp`）と、最初から TLS の待ち受けに対する
ハンドシェイクで、受け入れるスイートとグループを数え上げた。既定値は Postfix 自身の出力（`postconf -d`）から採った。
設定ファイルの読み方（継続行、コメント、後勝ち、`$名前` の展開、`-o` の上書き）も、Postfix 自身（`postconf`）が同じファイルをどう読むかを正解にしている。

Postfix で分かったこと:

- **Postfix は OpenSSL のセキュリティレベルを 0 にする。** システムの openssl.cnf の暗号文字列もレベルも効かない。RHEL 9.9 / 10.3（暗号ポリシーはレベル 2）でも、
  TLS 1.0 / 1.1 で使われるスイートを受け入れる。既定の表に、アプリが決めるレベル（`tls.security-level`）を持たせた。
- **既定で、認証なし（匿名）のスイートを受け入れる。** 等級の暗号文字列が `aNULL` を含むため。RHEL と Ubuntu が配る設定（STARTTLS は任意、証明書あり）のままで、
  56〜68 個のスイートを受け入れ、そのうち 12〜16 個が匿名。除外するには `smtpd_tls_exclude_ciphers = aNULL` が要る。
- **暗号は「等級」で決まる。** 任意のときは `smtpd_tls_ciphers`、必須のときは `smtpd_tls_mandatory_ciphers` の等級を使い、等級に対応する暗号文字列
  （`tls_<等級>_cipherlist`）に除外の指定を「:!名前」として足したものが OpenSSL に渡る。この予測は 96 場面すべてで実測と一致した。
- **最初から TLS の待ち受け（`smtpd_tls_wrappermode = yes`）は、水準の指定が「任意」のままでも、「必須」のときの等級を使う。**
- **等級の暗号文字列は、版で違う。** 3.8 以降は、古い方式（3DES、RC4、SEED、IDEA、固定の DH など）を除く形になり、等級 low と export は空になった。
- **鍵交換のグループは Postfix 自身が決め、耐量子のハイブリッドを受け入れない。** OpenSSL 3.5 の上の 3.5.25（RHEL 9.9）、3.8.5（RHEL 10.3）、3.10.13（Debian 13）のいずれも、
  X25519・X448・P-256・P-384・P-521（3.8 以降は ffdhe2048・ffdhe3072 も）だけ。RHEL 10 の暗号ポリシーがハイブリッドを並べていても、Postfix には効かない。
- **古い書き方の等級（`smtpd_tls_eecdh_grade = ultra` など）は、3.5 までは効き（その曲線だけになる）、3.6 以降は効かない。**
- **TLS 1.3 のスイートは Postfix が設定しない。** システムの設定（RHEL の暗号ポリシーの 4 個）、なければライブラリの既定（3 個）になる。
- **証明書なし（`smtpd_tls_cert_file = none`）では、匿名のスイートだけになり、TLS 1.3 は使えない。** TLS 1.3 専用のグループ（有限体 DH）も使われない。
- **ディストリが配る設定:** RHEL 8 / 9 / 10 と Ubuntu 16.04〜24.04 は、導入しただけで TLS が有効（証明書の指定と、STARTTLS が任意の設定）。Debian 13 は TLS の指定がない。

PostgreSQL の測定（2026-11-13）: RHEL 系は UBI のリポジトリにサーバーのパッケージがないため、AlmaLinux の公式イメージ（8.10、9.8、10.2）で測り、
出典にそのイメージを記録した。AlmaLinux 9 / 10 の OpenSSL は UBI と版が違う（3.5.8-2）ので、暗号スイートとグループの対応表も AlmaLinux で採って足した
（AlmaLinux 8 の OpenSSL は UBI 8 と同じ版）。既定値は、起動したサーバー自身の答え（`pg_settings` の `boot_val`）から採り、
設定ファイルの読み方（後勝ち、`include`、`include_dir`、`postgresql.auto.conf`、引用符の書き方）も、サーバー自身の答えを正解にした。
接続は `openssl s_client -starttls postgres`。

PostgreSQL で分かったこと:

- **既定の暗号文字列は、10 から 17 まで同じ**（`HIGH:MEDIUM:+3DES:!aNULL`）。セキュリティレベルと TLS 1.3 のスイートは、システムの設定に従う。
- **鍵交換のグループは `ssl_ecdh_curve` の 1 つだけ（既定は prime256v1）で、TLS 1.3 でもそのグループだけになる。** X25519 も受け入れず、
  OpenSSL 3.5 の上でも耐量子のハイブリッドを受け入れない。複数のグループを書ける `ssl_groups` は PostgreSQL 18 からで、今回の範囲には 18 がなく測れていない。
- **DH パラメータの指定がなくても、組み込みのパラメータで DHE を使える。**
- **ALTER SYSTEM で書かれた値（データディレクトリの `postgresql.auto.conf`）は、`postgresql.conf` より優先される。** 設定ファイルだけを見ると見落とす。
- **ディストリが配る設定:** Debian・Ubuntu は、導入しただけで `ssl = on`（自己署名の証明書）。RHEL 系は `ssl` の指定がなく、TLS は無効。
- Ubuntu 16.04（PostgreSQL 9.5、OpenSSL 1.0.2）は、試す側の `openssl` が PostgreSQL の接続開始の手順に対応しておらず、測れていない（既定値表がなく「不明」になる）。

Dovecot の測定（2026-11-13）: imaps（993）と pop3s（995）へのハンドシェイクで数え上げた。既定値は Dovecot 自身の出力（`doveconf -d`）、
設定の読み方（取り込みの順、後勝ち、プロトコルごとの上書き）も Dovecot 自身の出力（`doveconf -n`、`doveconf -f protocol=imap`）を正解にした。RHEL 系は AlmaLinux で測った。

Dovecot で分かったこと:

- **RHEL 系が配る設定の `ssl_cipher_list = PROFILE=SYSTEM` は、実際には暗号ポリシーの暗号文字列として働いていない。**
  接続を受けるプロセス（imap-login など）は既定で chroot の中で動き、暗号ポリシーのファイルを読めないため、ライブラリの既定（`DEFAULT`）になる。
  AlmaLinux 8 / 9 / 10 のいずれでも、受け入れたスイートは `DEFAULT` の展開と一致し、chroot を外した設定では暗号ポリシーの展開と一致した。
  `PROFILE=SYSTEM:!kRSA` のように続きを書くと、`DEFAULT:!kRSA` として働く。暗号ポリシーが鍵交換の RSA を外している AlmaLinux 10 でも、配られる設定のままでは受け入れる。
  既定の表に、この挙動（`tls.profile-in-chroot`）を持たせ、実際に効く暗号文字列で求めて、理由を結果に添える。
- **鍵交換のグループと TLS 1.3 のスイートは、Dovecot 自身の既定を持たない。** システムの openssl.cnf（これは chroot の前に読まれる）、なければライブラリの既定に従う。
  このため、Debian 13（OpenSSL 3.5）と AlmaLinux 10（暗号ポリシー）の Dovecot は、何も設定しなくても耐量子のハイブリッドを受け入れる。
- **DHE は、DH パラメータのファイルを指定したときだけ使える**（2.3 以降）。Ubuntu が配る設定はファイルを指定しており、RHEL 系と Debian 13 は指定していない。
  2.2 は、自分で生成したパラメータで使える。
- **証明書などの項目の名前が、2.4 で変わった**（`ssl_cert = <ファイル` → `ssl_server_cert_file = ファイル` など）。どちらも読む。
- **ディストリが配る設定:** RHEL 系と Debian・Ubuntu 20.04 以降は、導入しただけで TLS が有効。

MariaDB / MySQL の測定（2026-11-13）: 2 つは設定ファイルの形が同じ（my.cnf）で、パッケージが排他なので別々に測った。既定値は起動したサーバーの変数、
設定の読み方（グループ、後勝ち、項目名の「-」と「_」）はサーバー自身の読み取り（`my_print_defaults`）を正解にした。
`openssl s_client -starttls mysql` は新しい MariaDB の最初の応答を受け付けなかったため、TLS を始める前のやりとりだけを代行する中継
（`lab/phase1d/mysql-tlsproxy.py`。コンテナの中の 127.0.0.1 だけで待ち受ける）を通して測った。

MariaDB / MySQL で分かったこと:

- **MariaDB は、暗号の指定がなければ何も設定しない**（OpenSSL のシステム既定。RHEL 系では暗号ポリシー）。グループと TLS 1.3 のスイートもシステムの設定に従うので、
  Debian 13 と AlmaLinux 10 では、何も設定しなくても耐量子のハイブリッドを受け入れる。
- **MariaDB は、証明書の指定がなければ、10.x は TLS が無効、11.8 は自分で用意した証明書で有効。**
- **MySQL は、暗号の既定を内蔵していて、サーバーの変数には現れない。** 実行ファイルに埋め込まれた並びの組み合わせのうち、実測と一致するものを既定の表に入れた。
  8.4 は 8.0 より大きく絞られている（RSA の証明書で 20 個 → 8 個）。
- **MySQL は、設定に書いた暗号文字列の後ろに「拒否する暗号」の並びを足す。** 8.4 は、弱い暗号を指定すると起動そのものを拒否する。
- **MySQL は、鍵交換のグループを自分で決める（P-256、P-384、P-521）。** X25519 も受け入れず、どのディストリでも耐量子のハイブリッドを受け入れない。
- **MySQL は、証明書の指定がなくても、データディレクトリに自分で用意した証明書で TLS が有効。**
- 同じ設定ファイル（`/etc/my.cnf`）はクライアントだけの環境にもあるので、本体・ユニット・パッケージのいずれかがある場合にだけ、サービスとして報告する。

A ランクの優先順位の見直し（2026-11-13、利用者と確認）: 実利用の多さの見立てから、MySQL / MariaDB → Java 系（java.security、Tomcat、Spring Boot、WildFly）→ OpenSSH クライアント →
rsyslog・Zabbix → VPN（OpenVPN、strongSwan、Libreswan）→ 認証基盤（OpenLDAP、Samba、Kerberos、FreeIPA）→ 鍵ファイルの記録が中心のもの（BIND、OpenDKIM、certbot、WireGuard、
Kubernetes、Vault、LUKS、Keycloak）の順とした。BIND は、企業内の DNS の主流ではなく、暗号も署名と共通鍵が中心（いま記録された通信が将来解読される種類ではない）ため後ろに回した。
商用製品（Oracle、IBM、HULFT など）は、ラボで動かせないので実測の対象外。

レポートの構成の見直し（2026-11-13、利用者の指摘 2 回分）: 名称を「クリプトインベントリ」に。要点は 4 つの枠（サービスの設定、ファイルとして見つかった証明書・鍵、証明書ストア、探索した範囲。
探索の起点もここに示す）。「このレポートでは分からないこと」と「判定の基準と出典」は、左の欄の「共通」から開く表示にして、ホストごとの表示には置かない。
レポートを作るときにホストごとの CBOM を作って埋め込み、リンクから保存できるようにした（スクリプトは使わない。合計 48 MB まで）。
設定からの参照を確認できなかった秘密鍵の一覧はやめ、「参照が見つからないことは、使われていないことを意味しない。削除の根拠にしない」という注意は共通の項目に残した。
証明書ストアの件数は、ストアごとの延べ数（同じ CA 証明書が複数のファイルやストアにあれば、その数だけ数える。ストアをまたいで足さない）。

差分テストで分かった、既知の限界の現れ方: 暗号文字列が IDEA のスイート（TLS 1.1 以下でしか使えない）を含み、サーバーが TLS 1.2 未満を受け付けない場合、
kagiya の一覧にはそのスイートが残る（AlmaLinux 8 で 1 個）。一覧は「いずれかの版が有効なら受け入れ得るもの」で、プロトコルの版による絞り込みはしていないため。

差分テストで見つかった不具合（Postfix）: 証明書のないサービスについて、kagiya が TLS 1.3 専用のグループ（ffdhe）も受け入れると答えていた（3 件）。
測定側も、証明書を前提にしたスイートでしかグループを試しておらず、最初は実測できていなかった。匿名の ECDH でも試すように測定を直したうえで、実装を直した。

差分テストで見つかった不具合: 最初の実装では、実際のスキャン結果に `haproxy` のパッケージ情報が入らず、版ごとの既定を引けていなかった
（記録対象のパッケージ名の一覧に足していなかった）。単体テストはパッケージを直接与えるため通っていた。
ルールが参照するパッケージが記録対象に入っていることを確かめるテスト（`TestRulePackagesAreRecorded`）を足して、再発を防いでいる。

---

## 6. Java（JDK、Tomcat、Spring Boot）

### Java 系の対応（2026-11-13〜、検証ラボ、arm64）

Java 系の進め方と、JAR の中の設定の読み取り（2026-11-13、利用者と確認）:

Java 系は 3 段で進める。(1) JDK の層: ディストリの OpenJDK ごとの TLS の既定と、`java.security`・RHEL の暗号ポリシーの効き方。
(2) Tomcat: 実物を起動し、`server.xml` の書き方を変えた場面ごとに測る。(3) Spring Boot: ラボで最小のアプリを作り、`application.properties` / `application.yml` の
指定を変えた場面ごとに測る。素の Java の TLS サーバーの測定は (1) の土台であって、アプリが自分で持つ既定や設定の効き方は (2)(3) で実物から確かめる。

Spring Boot は設定が実行可能 JAR の中にあるのが普通なので、JAR（zip）の中の設定も読む。利用者から、非機能要件に配慮することを条件に了承を得た。守ること:

- **書き込まない。** JAR はディスクに展開せず、必要なエントリだけをメモリ上で読む。
- **読むエントリを限る。** 決まった名前の設定ファイル（`BOOT-INF/classes/application*.properties` / `.yml` など、ルールで定めたもの）だけを開く。入れ子の JAR は開かない。
- **上限を設ける。** JAR の大きさ、エントリの数、1 エントリの圧縮後・展開後の大きさ、展開の倍率、読む JAR の数。上限を超えたものは開かず、読み飛ばしたことを記録する。
- **壊れた zip・悪意のある zip で止まらない。** 中央ディレクトリの矛盾、重複した名前、パスに「..」を含む名前、展開すると巨大になるもの（zip 爆弾）などは、問題として記録して読まない。
- **秘密を抜き出さない。** 取り出すのは、あらかじめルールで許可した項目（暗号スイート、プロトコル、キーストアの場所と種類など）だけ。それ以外の項目は、名前も値も記録しない。
  許可した項目でも、値は種類ごとの検証を通ったものだけを記録する（パスワードの項目は許可しない）。
- **確度を下げる。** JAR の中の設定は、外に置いた設定・環境変数・起動時の引数・プロファイルに上書きされ得る。結果には「JAR の中の設定。外からの上書きは確認していない」と注記する。

Java 系の (1) JDK の層の結果（2026-11-13、検証ラボ、arm64）:

8 つのディストリ（AlmaLinux 8 / 9 / 10、Debian 13、Ubuntu 16.04 / 20.04 / 22.04 / 24.04）の OpenJDK 8 / 11 / 17 / 21 / 25（27 個）を測った。
kagiya は、導入されている JDK ごとに、Java を動かさずに、既定で受け入れるプロトコル・暗号スイート・鍵交換のグループを求める
（結果では、アプリ `openjdk` の、JDK のディレクトリごとの範囲として出る）。

| 部分 | 場所 | 内容 |
|---|---|---|
| 対応表 | `rules/java/openjdk.yaml` | パッケージ版ごとの、対応しているプロトコル・スイート・グループと、解釈の版による違い（17 個の表） |
| 無効にする方式の解釈 | `internal/jsse` | `jdk.tls.disabledAlgorithms` の項目を、スイートの名前の部品・プロトコル・グループと照合する |
| 設定ファイルの読み取り | `internal/parse/javasecurity` | `java.security` と、そこから取り込まれるファイル |
| 収集 | `internal/collect/apps/java.go` | JDK のディレクトリとパッケージの対応、暗号ポリシーとのつなぎ、実効値の記録 |

実物で確かめた事実:

- **正解の取り方。** スイートとプロトコルは JDK 自身の報告（サーバーソケットで有効なもの）を正解にした。グループは、同じコンテナ内で Java の TLS サーバーを起動し、
  グループを 1 つだけ示した ClientHello を直接組み立てて送って確かめた（`lab/phase2/grpprobe.py`）。最初は `openssl s_client` で数えていたが、
  試す側の OpenSSL が古いと有限体 DH や耐量子のハイブリッドを試せず、「受け入れない」と誤って記録していた（Ubuntu 24.04 の JDK 25 の X25519MLKEM768 など）。
  JDK 自身が API で答えるグループの一覧（JDK 20 以降）には、無効にする方式が反映されないので、正解には使えない。
- **耐量子のハイブリッド。** X25519MLKEM768 を既定で受け入れるのは JDK 25 から。21 以前は受け入れない。
- **表は、配布元ではなく開発元の版で決まっていた。** 同じ Java の版なら、AlmaLinux・Debian・Ubuntu で、対応しているスイート・プロトコル・グループは同じだった
  （8u292 だけ、スイートの並びが違う）。版によって違ったのは、解釈のしかた（下の 2 点）だけ。
- **名前のパターン（`TLS_RSA_*`）を解釈するかは版による。** 11.0.25、17.0.15、21.0.7 と Java 8 は解釈せず（その項目は何も無効にしない）、11.0.33、17.0.21、21.0.13、25 は解釈する。
- **グループの名前の無効化。** `jdk.tls.disabledAlgorithms` にグループの名前を書くと受け入れなくなる（大文字小文字を区別しない。`include` での取り込みも効く）。
  Java 8 だけは効かない。鍵長の条件（`EC keySize < 384`、`DH keySize < 3072`）は、どの版でもグループに及ぶ（X25519 などには及ばない）。
- **スイートの一覧とプロトコル。** TLS 1.3 を無効にすると TLS 1.3 のスイートが、TLS 1.2 を無効にすると認証付き暗号と SHA-256 / SHA-384 の MAC のスイートが、既定の一覧から消える。
  再ネゴシエーションの印（`TLS_EMPTY_RENEGOTIATION_INFO_SCSV`）は、TLS 1.2 以下のどれかが有効なときだけ一覧に入る（kagiya は、これを暗号スイートとして出さない）。
- **Java 8 の DHE。** クライアントが有限体 DH のグループを示さない場合、1024 ビットのパラメータを使う（11 以降は 2048 ビット）。
- **RHEL 系の暗号ポリシーとのつなぎ方は 2 通り。** JDK 8 / 11 / 17 / 21 は、`java.security` の `security.useSystemPropertiesFile=true` により、
  `/etc/crypto-policies/back-ends/java.config` の値が置き換える。JDK 25 は、`java.security` の `include redhat/${redhat.crypto-policies}/crypto-policies.properties` から、
  `conf/security/redhat` の下のファイルを経て同じファイルを取り込む（`${名前}` は、起動時の指定がなければ空になる）。
  JDK 25 では、連動を切る従来の起動オプション（`-Djava.security.disableSystemPropertiesFile=true`）は効かない。
  どちらのつなぎ方も、その読み方で組み立てた値が JDK 自身の報告と一致することを確かめた版にだけ、表に印を付けて使う。

確かめた件数: 無効にする方式の解釈は、場面を変えた 306 件（JDK 自身の報告とハンドシェイク）と一致。ファイルから組み立てた設定値は 152 件で JDK の報告と一致。
コンテナの中で kagiya を実行した結果は、27 個の JDK の 108 項目（プロトコル、TLS 1.2 以下のスイート、TLS 1.3 のスイート、グループ）すべてで実測と一致
（`lab/phase2/java-diff.py`）。

評価のための変更: Java の結果はスイートを標準名（`TLS_ECDHE_RSA_WITH_...`）で出すので、標準名からも属性（鍵交換、認証、暗号化、MAC）を引けるようにした。
OpenSSL の対応表にないスイート（固定鍵の ECDH など）は、名前の部品から属性を求める。対応表にあるスイートでは、名前から求めた属性が対応表と一致することをテストで確かめている。

配布元をまたぐ補間（2026-11-13、利用者と確認。実装済み）: 上の「表は開発元の版で決まっていた」を受けて、Java に限り、開発元の版が同じなら
配布元が違っても既存の表で補うことにした（確度を下げ、注記を付ける）。利用者の指示は「検証が通った場合に限る」「Java に特化したこの判断が、別の機能に流出しないようにする」。

- **検証。** 配布元の公式イメージの JDK（Eclipse Temurin 8 / 11 / 17 / 21 / 25、Amazon Corretto 8 / 17 / 21）を、ディストリの JDK と同じ場面で測った。
  8 個すべてで、開発元の版が同じディストリの表と、対応しているプロトコル・スイート（並びを含む）・グループ、解釈の版による違い、DHE の既定の鍵長が同じだった。
  使ったイメージと結果は `rules/java/openjdk.yaml` の冒頭に記録している。生成スクリプトは、表を作るたびにこの一致を確かめ直し、崩れていれば生成を止める。
- **引き方。** JDK のディレクトリにある `release` ファイルの `JAVA_VERSION`（`21.0.13`、`1.8.0_512` など）が、表の `java_version` と完全に一致する場合に限る
  （Ubuntu の `21.0.13.0.3` は `21.0.13` とは別の版）。同じ版の表が複数あって中身が食い違えば、補わない。
  パッケージの版で表が見つかる場合（実測した版、同じ系列でリリースだけ違う版）は、これまでどおりそちらを使う。
- **引き継がないもの。** 暗号ポリシーとのつなぎ方（RHEL 系の `security.useSystemPropertiesFile` と `include`）は、測ったディストリの JDK のものなので引き継がない。
  配布元の違う JDK の `java.security` に同じ仕組みの記載があれば、「不明」とする。
- **配布元ごとの違いの現れ方。** 何を無効にするかは、その JDK 自身の `java.security` から読むので、配布元ごとの既定の違いは結果に反映される
  （Corretto 8 は、TLS 1.0 と 1.1 を無効にしていない。実測と一致）。
- **ほかの機能に広げないための作り。** JDK の表だけが通る別の引き方（`ruleset.JDKTableForJavaVersion`）にし、共通の引き方（`findBuild`）は変えていない。
  暗号スイートとグループの対応表、アプリの既定値表が、配布元やディストリをまたいで当たらないことを、テスト（`TestBuiltinJDKTableForJavaVersion`）で確かめている。
- **探す場所。** `/usr/lib/jvm/<名前>/`（Corretto の rpm はここに入る）と、Temurin の公式イメージの配置（`/opt/java/openjdk`）。それ以外の場所に展開された JDK は、まだ見つけない。

Temurin の測定で分かったこと: TLS 1.2 を無効にして、それより古いプロトコルを有効にした設定でも、ECDHE のグループは受け入れ続ける（古いプロトコルでの鍵交換に使われる）。
それまで測っておらず「求められない」としていたが、求めるようにした。

測定の所要時間（2026-11-13、実測）: Java の測定では、`openssl s_client` でのスイートの数え上げは 1 場面あたり約 5 秒、ClientHello を直接組み立てる方式
（`lab/phase2/tlsenum.py`）は約 1 秒で、どちらも全体の中では小さい。時間がかかるのは、パッケージの導入（ミラーが遅いと 1 回 15 分ほど）と、場面を足すたびの全体の測り直し。
後者のために、場面を選んで測り直す指定（`ONLY_SCENES`）を足した。直接組み立てる方式の利点は、速さより、試す側の OpenSSL が持たないスイートやグループも試せること。

見せ方（2026-11-14、利用者が決定）: JDK は、ほかのソフトウェアと同じ 1 つとして数える。レポートの見出しは「ソフトウェアが用いる暗号の状況（計 N ソフト）」
「各ソフトでの暗号利用状況」とした。

#### Tomcat（2026-11-14、検証ラボ、arm64）

Java の 2 段目として、ディストリのパッケージで導入した Tomcat（9.0.31 / 9.0.58 / 9.0.121 / 10.1.49 / 10.1.55 / 10.1.60 / 11.0.22。8 環境）を実際に起動して測った。
分かったことと、それに合わせた作り:

- **TLS の実装が 2 通りある。** JDK の実装（JSSE）と、OpenSSL の実装（Tomcat Native というライブラリを通す）。`sslImplementationName` で明示していなければ、
  `AprLifecycleListener` があり、Tomcat Native を読み込めたときに OpenSSL の実装になる。Tomcat Native は、Tomcat の版が求める版より古いと読み込まれない
  （Debian 13 は 1.3.1 で、10.1.60 が求める 1.3.9 に足りず、JDK の実装で動く。Ubuntu 20.04 / 22.04 / 24.04 は読み込まれ、OpenSSL の実装で動く）。
  求める版は Tomcat 自身の定数から採取して表に持ち、導入されているパッケージの版と比べる。
- **暗号指定は Tomcat が自分の表で解釈する。** `ciphers` は OpenSSL の書き方だが、JDK の実装では OpenSSL には渡らない。語が指すスイート（HIGH など約 600 語）と
  スイートの表（264 個）を、版ごとに Tomcat 自身のクラスに出力させて表にした（`rules/java/tomcat.yaml`）。式の読み方は `internal/tomcatciphers` にあり、
  Tomcat 自身の解釈結果と、8 環境・延べ 42,173 式で集合として一致することを確かめた（生成スクリプトが、表を作るたびに確かめ直す）。
  並び順（`+語`、`@STRENGTH`）は版によって違い、再現していない（受け入れるスイートの集合には影響しない）。
- **JDK の実装での結果 = Tomcat の解釈 ∩ JDK が対応するもの − JDK が無効にしたもの。** JDK の側は、1 段目の表と読み取り（`jdkRead`）をそのまま使う。
  アプリが自分で一覧を指定する場合の求め方として `jsse.ResolveExplicit` を足した。
- **版ごとに違ったこと（表に持つ）:** 既定の暗号指定（`!EXPORT` の有無）、`@STRENGTH` の後ろの要素を読むか、TLS 1.3 のスイートを別の属性（`cipherSuites`）で持つか、
  その属性が JDK の実装で効くか（測った 3 つの版では効かなかった）、古い書き方（Connector に直接書く TLS 設定）で起動するか（10.1 以降は起動しない）。
  同じ 10.1 系でも、AlmaLinux 10 の 10.1.49 は古い側、Debian 13 の 10.1.60 は新しい側の挙動だった。上流の版の大小では決められない。
- **「受け入れる」の定義を固定した。** Tomcat は、クライアントが示したスイートの並びを見て証明書を選ぶ。RSA と EC の証明書を両方置くと、候補をまとめて示す数え上げでは
  ECDSA のスイートが現れなかった（14 個）。1 つずつ示すと 21 個。以後、「そのスイートだけを示したクライアントがつながるか」で数える（`lab/phase2/tlsone.py`）。
  結果は確率的には変わらないが、クライアントの示し方には依存する、ということ。
- **設定の意味からは説明できない挙動があった。** Ubuntu 24.04（Tomcat 10.1.55 + Tomcat Native 2.0.14 + OpenSSL 3.0.13）では、証明書を RSA → EC の順に書くと
  TLS 1.3 を受け入れない（EC → RSA の順、または片方だけなら受け入れる。`openssl s_client` でも確認）。Ubuntu 20.04 / 22.04 では起きない。
  OpenSSL の実装の経路は、こうした版ごとの事実を表に持つ前提で作る（未実装）。
- **`server.xml` の読み方。** 決まった要素（Listener、Connector、SSLHostConfig、Certificate）の、決まった属性だけを取り出す（`internal/parse/serverxml`）。
  パスワードの属性は名前の一覧にないので読まない。外部のものは読みに行かず（Go の `encoding/xml` は実体の定義を解釈しない）、`DOCTYPE` があれば値を求めない。
- **Java のセキュリティプロバイダ。** `java.security` に JDK 以外のプロバイダ（BouncyCastle など）が登録されていれば、JDK の表を当てはめず「不明」にする
  （JDK だけの結果にも、Tomcat の結果にも効く）。

OpenSSL の実装で動く場合（2026-11-14）: この実装では、Tomcat は `ciphers` の値を自分では解釈せず、そのまま OpenSSL に渡す。実測（Ubuntu 20.04 / 22.04 / 24.04）は
「その文字列を、導入されている OpenSSL の表で展開し、証明書の種類で絞ったもの」と一致したので、OpenSSL を使うほかのサーバーと同じ求め方
（`opensslServerEffective`）に渡している。Tomcat の側で足したのは、範囲の作り方（`tomcatOpenSSLScope`）と、版ごとの既定（`rules/defaults/tomcat.yaml`。生成スクリプトが実測から作る）だけ。
共通の求め方には、証明書の種類をファイルを読まずに与える指定、プロトコルの版が有効でないときにスイートを空にする指定、TLS 1.2 以下だけを求めない指定を足した。
証明書を複数置いた場合の扱い（`tls.multiple-certificates`）は、「両方の証明書の場面の結果 = 片方ずつの場面の結果の和集合」が、並び順を入れ替えても成り立つかで決める。
成り立ったのは Ubuntu 20.04 だけで、22.04 / 24.04 は並び順に依存した。依存する版では、証明書を複数置いた設定の値は求めない。

測定の効率化（2026-11-14、利用者と確認）: apt / dnf がダウンロードしたパッケージを `lab/cache/` に残して使い回す（`lab/phase1d/common.sh` の `setup_package_cache`）。
導入そのものは毎回やり直し、リポジトリの一覧も毎回取り直すので、測る対象は毎回まっさらで、更新された版があればそれが入る。
導入済みのイメージを保存して使い回す方法は、古い状態で測り続けるおそれがあるので、いまは採っていない。

差分テスト（`lab/phase2/tomcat-diff.py`）: コンテナの中で kagiya に各場面の `server.xml` から求めさせ、同じ設定で起動した Tomcat の実測と比べる。
求めない場合（OpenSSL の実装、表のない JDK）と、設定の誤りで起動しない場面は、別の分類で数える。
結果（2026-11-14、8 環境・延べ 286 場面）: 暗号スイートとプロトコルの一致 202、鍵交換のグループの一致 200、不一致 0。
求めなかったもの 83（証明書を複数置いた OpenSSL の実装の場面が大半。ほかに、起動しない書き方の場面、`cipherSuites` や `groups` を書いた一部の場面、
版によって挙動が違う `SSLEngine="off"`）。起動しない設定に値を出したもの 1（JDK が対応するスイートが残らない暗号指定）。
証明書を複数置くと求めない版（Ubuntu 22.04 / 24.04）でも設定の効き方を確かめられるよう、証明書 1 つ（RSA）の場面を 14 個足して測った
（5 環境。Ubuntu 22.04 / 24.04 の一致は 6 / 5 → 17 / 15）。
最初の突き合わせで見つかって直したもの: `groups` と EC の証明書の組み合わせ、10.1 以降で起動しない古い書き方、JDK の実装で効かない `cipherSuites`、
AlmaLinux 8 の Java 8 の表がなかったこと（リポジトリの更新。測り直して追加）。
TLS 1.3 のスイートが残らない設定で TLS 1.3 専用のグループを答えていたこと（グループは、それを使うスイートが残っているときだけ出すようにした）。
OpenSSL の実装で TLS 1.3 を有効にしていない設定でも、TLS 1.3 専用のグループを答えていたこと（証明書 1 つの場面を足して見つかった。OpenSSL を使うサーバーに共通の箇所を直した）。

ライブラリの扱い（2026-11-14、利用者と確認）: 暗号ライブラリ（BouncyCastle など）は、棚卸し（どの版があるか）、Java のプロバイダの確認、BouncyCastle 形式の
キーストアの識別までを扱う。アプリがライブラリのどの機能を呼んでいるか（コードやクラスファイルの解析）は対象外とし、別種のツールに任せる。


#### Spring Boot（2026-11-14、検証ラボ、arm64）

Java の 3 段目として、Spring Boot のアプリ（組み込みの Tomcat で TLS を待ち受ける、実行できる JAR）に対応した。

- **測定の範囲（利用者が決定）:** 2.7 以降の全パッチ版（2.7.0〜4.1.2 の 117 版）。補間はしない。各版の最小のアプリ（spring-boot-starter-web）を、
  Docker 公式の maven イメージで Maven Central の成果物からビルドし、Ubuntu 24.04 の OpenJDK 21 で実際に起動して、JAR の中の設定を変えた 22 場面ごとに
  ハンドシェイクで数え上げた（`lab/phase2/springboot-all.sh`。3 並行で約 1 時間半）。ビルドした JAR は測定の後に消し、リポジトリには入れていない。
- **JAR の構造:** マニフェストに `Spring-Boot-Version`、設定は `BOOT-INF/classes/application.properties`（または `.yml`）、同梱ライブラリは `BOOT-INF/lib/` に
  JAR のまま（圧縮なし）入っている。同梱の Tomcat の版は、ファイル名（`tomcat-embed-core-<版>.jar`）から分かる。入れ子の JAR を開く必要はない。
- **同梱の Tomcat の表:** 117 版に同梱されていた Tomcat は 62 版。それぞれに、暗号指定の解釈を Tomcat 自身のクラスに出力させた（パッケージの Tomcat と同じ採取）。
  中身は 6 通りにまとまり、版ごとに JAR のチェックサムを出典として持つ（`rules/java/tomcat-embedded.yaml`）。延べ 334,180 式で、Tomcat 自身の解釈結果と一致。
  同じ上流の版（10.1.55）の Ubuntu のパッケージの表と、中身は同じだった。
- **設定の効き方（どの版でも同じだったこと）:** `server.ssl.enabled-protocols` と `server.ssl.ciphers` が効く。`server.ssl.protocol` は絞り込みには効かない。
  `ciphers` を書くと、TLS 1.3 のスイートもその指定に従う（パッケージの Tomcat の `server.xml` では、`ciphers` に何を書いても TLS 1.3 は既定のままだった。
  同じ Tomcat でも、Spring Boot 経由だと設定の渡り方が違う）。同じ場所では `.properties` が `.yml` に勝つ。有効にしたプロファイルの設定が上書きし、
  有効でないプロファイルの設定は効かない。キーストアや証明書の指定がない、または `server.ssl.enabled=false` なら、TLS を待ち受けない。
- **版によって違ったこと（`rules/java/springboot.yaml`）:** SSL バンドル（`server.ssl.bundle`、`spring.ssl.bundle.*`）は 3.1 以降。2.7 系と 3.0 系では、書いても TLS を待ち受けない。
  PEM での指定（`server.ssl.certificate`）は、2.7.0 と 2.7.1 では起動しなかった。3.4.0 は、バンドルの 3 場面で起動しなかった（同じ版の中で一貫しているが、測り直してはいない）。
- **参照モデルとの突き合わせ:** 117 版・2,574 場面のうち 2,470 場面で一致。合わなかった 99 場面と起動しなかった 5 場面は、上の「版によって違ったこと」だけだった。
- **どの JDK で動くか（利用者と確認）:** JAR だけでは分からないので、起動の定義（systemd のユニットの `ExecStart` の `java -jar`）から読む。
  定義が読めない JAR は、導入されているすべての JDK で結果を求め、同じになった項目だけ確定とする（違う項目は「不明」にして、JDK ごとの結果を理由に並べる）。
  init.d のスクリプト、自作の起動スクリプト、ジョブ管理ツールの定義は解釈せず、実行中のプロセスも見ない。
- **JAR の外からの上書き:** 起動時の引数（`--server.ssl...`、`--spring.config.location` など）、環境変数（`SERVER_SSL_...` など）、JAR の隣の設定ファイルが見つかった場合は、値を求めない。
  プロファイルの指定（`--spring.profiles.active`、`SPRING_PROFILES_ACTIVE`）は読み、設定ファイルの中の指定より優先する。見つからなかった場合も、
  「JAR の外からの上書きは確認していない」と注記する。
- **秘密を持たない作り:** 設定から取り出すのは、許可した項目だけ（`internal/parse/springconf`）。パスワードの項目は許可していない。鍵や証明書の中身を直接書ける項目は、
  値が場所の形のときだけ持つ。起動コマンドは、Java の実行ファイル、JAR、プロファイルだけを読み、ほかの引数は「TLS の設定を変えうるものがあったか」だけを見る。
- **差分テスト（`lab/phase2/springboot-diff.py`）:** 系列ごとの代表 12 版（2.7.0 / 2.7.2 / 2.7.18 / 3.0.13 / 3.1.12 / 3.2.12 / 3.3.13 / 3.4.0 / 3.4.13 / 3.5.16 / 4.0.9 / 4.1.2）の
  延べ 264 場面で、コンテナの中の kagiya の結果と実測を比べた。一致 224、TLS を待ち受けない設定で kagiya も値を出さなかったもの 36、
  求めなかったもの 4（起動しなかった場面）、不一致 0。この比較は「起動の定義がない」経路（JDK が 1 つなので確定）で行った。
  ユニットから JDK を読む経路は、2 版（3.5.16、2.7.18）の 44 場面で、ユニットを置いた状態でも比べた（一致 37、TLS なし 7、不一致 0。
  `/usr/bin/java` からディストリのリンクを辿って JDK に行き着くこと、確度が「高」になること、「起動するよう設定されている」と記録されることも確かめた）。
- **supervisord の定義（2026-11-14）:** supervisord のプログラム（`/etc/supervisor/supervisord.conf`、`/etc/supervisor/conf.d/*.conf`）も起動の定義として読む
  （`internal/parse/supervisorconf`）。読み方（引用符、`;` のコメント、`environment=`、`directory=`、`%(...)s` の置き換え）は、Ubuntu 24.04 の
  supervisor 4.2.5-1ubuntu0.1 に実際にプログラムを起動させ、プロセスに渡った引数・環境変数・作業ディレクトリを見て確かめた（`lab/phase2/supervisor-explore.sh`）。
  置き換えは解釈せず、コマンドに置き換えがあれば起動の定義なしとして扱い、結果に関わる環境変数に置き換えがあれば値を求めない。
  「起動するよう設定されている」とするのは、`supervisor.service` が有効で、プログラムが `autostart=false` でない場合。
- **そのまま実行できる JAR（2026-11-14）:** ビルドの設定で `executable` を有効にすると、JAR の先頭に起動スクリプトが付き、JAR そのものを起動できる。
  Spring Boot 2.7.18 と 3.5.16 でビルドした JAR からスクリプトを取り出して読んだ（`lab/phase2/springboot-exec.sh`。どちらも同じ内容の 309 行。
  4.1.2 では、同じ設定でもスクリプトは付かず、ビルドの道具にもスクリプトが含まれていなかった。4.0 系のどの版でなくなったかは調べていない）。
  スクリプトは、JAR の隣（環境変数 `CONF_FOLDER` があればその場所）の `<JAR の名前>.conf` をシェルとして取り込み、`JAVA_HOME` の下に java があればそれを、
  なければ PATH の java を使い、JAR のあるディレクトリで `java $JAVA_OPTS -jar <JAR> $RUN_ARGS <引数>` を起動する。
  - kagiya は、起動の定義（systemd のユニット、supervisord のプログラム）が JAR そのものを起動している場合に、`.conf` と定義の環境変数から、Java と起動時の指定を読む
    （`internal/collect/apps/executable.go`）。`.conf` はシェルとして実行せず、「名前=値」だけを読む（`internal/parse/shellconf`）。値を取り出すのは
    `JAVA_HOME` / `JAVA_OPTS` / `RUN_ARGS` だけで、展開（`$...`）を含む値、代入でない行、TLS の設定に関わる環境変数の代入があれば、値を求めない。
  - `JAVA_HOME` から Java が決まらない場合（PATH の java）は、どの JDK かを決めず、すべての JDK で同じになる項目だけ確定とする（確度は下げる）。
  - 起動の定義がない場合は、スクリプトとして起動されているかが分からない。`.conf` に結果を変える指定（TLS の設定の上書き、プロファイル、Java の TLS に関わる起動オプション）
    があれば値を求めず、なければ `.conf` がない場合と同じに扱う（`JAVA_HOME` は使わない）。
  - 実測（`lab/phase2/springboot-execrun.sh`、Ubuntu 24.04、openjdk-17-jre-headless 17.0.21.0.3+1-1~24.04.1 と openjdk-21-jre-headless 21.0.13.0.3+1-1~24.04.1、
    Spring Boot 3.5.16）: JAR をスクリプトとして起動し、`/proc` でプロセスの実行ファイル・引数・作業ディレクトリを見た。`.conf` の `JAVA_HOME` の Java で動くこと、
    `.conf` の値がユニットの環境変数より優先されること、`CONF_FOLDER`、`JAVA_OPTS`、`RUN_ARGS`、JAR の後ろの引数が上の通りに効くこと、
    `JAVA_HOME` がない（または、その下に java がない）場合は PATH の java（このコンテナでは 21）で動くことを確かめた。
    同じ状態で kagiya に求めさせた結果との突き合わせは、9 場面すべて一致（`JAVA_HOME` から決まる 7 場面は確度「高」、PATH の java になる 2 場面は確度「中」）。
    ビルドしたままの JAR（先頭にスクリプトがある）を、kagiya が Spring Boot のアプリとして読めることも確かめた。
- **管理用の待ち受け（2026-11-14）:** `management.server.port` で本体と別のポートにしたものは、TLS の設定がありうる場合に、別の待ち受けとして「不明」で記録する
  （待ち受けがあること自体を見落とさないため。値は求めない）。
- **まだ対応していないもの:** init.d から JAR を起動する形（リンクを置く形）、管理用の待ち受けの値（`management.server.ssl.*` の決まり方は測っていない）、
  クラスパスの `config/` の設定ファイル、Tomcat 以外の同梱サーバー（Jetty、Undertow、Netty）。

### 暗号ライブラリが耐量子のアルゴリズムに対応している版（2026-11-14、検証ラボ、arm64）

見つかった暗号ライブラリについて、「その版が耐量子の方式を持っているか」を結果（`components[].pqc`）とレポートに出すようにした。
「どの版から対応したか」は、開発元の資料だけでは決めきれないもの（どの版で入ったかが資料に書かれていない、資料のページが取得できない）があったので、
Maven Central の各版の実物を読み込んで、ライブラリ自身に尋ねて確かめた（`lab/phase2/pqc-libs.sh`、`PqcProbe.java`。鍵は作らず、通信もしない）。
OpenSSL は、ディストリのパッケージの `openssl list` で確かめた（`lab/phase2/openssl-pqc.sh`）。出典は、ルール（`rules/libraries/*.yaml` の `pqc`）に書いてある。

| ライブラリ | 確かめた範囲 | 結果 |
|---|---|---|
| Bouncy Castle 本体（bcprov-jdk18on） | 1.71〜1.87 の全 22 版 | ML-KEM / ML-DSA / SLH-DSA は 1.79 から。1.72〜1.84 には標準化前の Kyber / Dilithium がある |
| Bouncy Castle の TLS（bctls-jdk18on） | 同じ | グループの定義: ML-KEM 単独（MLKEM512 / 768 / 1024）は 1.80 から、ハイブリッド（X25519MLKEM768 など 3 種）は 1.81 から |
| Bouncy Castle の FIPS 版（bc-fips） | 1.0.0〜2.1.3 の全 16 版 | 耐量子のアルゴリズムは、どの版にもない |
| Conscrypt（conscrypt-openjdk-uber） | 2.6.0〜2.9.0 の 7 版 | ML-KEM / ML-DSA / SLH-DSA がある。2.5.2 以前は arm64 向けを含まず測れなかった（開発元のリリースノートは、2.6.0 で入ったとしている） |
| Netty tcnative（boringssl-static、arm64） | 2.0.50〜2.0.85 の 36 版 | X25519MLKEM768 を設定できるのは 2.0.68 から（標準化前の X25519Kyber768Draft00 は 2.0.62 から）。2.0.67 と 2.0.76 は測れなかった |
| OpenSSL | 3.0.13（Ubuntu 24.04）、3.4.1（Ubuntu 25.04）、3.5.7（Debian 13）、3.5.8（AlmaLinux 9.8） | 3.0.13 と 3.4.1 にはなく、3.5.7 と 3.5.8 にはある（ML-KEM / ML-DSA / SLH-DSA と、ML-KEM を含む TLS のグループ）。「3.5.0 から」は開発元の NEWS.md による |

- **版の比べ方:** 数字の並びとして比べる。正式版でないもの（alpha、RC、SNAPSHOT など）は比べず、「不明」とする。
- **根拠の区別（`basis`）:** 実物で確かめた範囲の版は `measured`、開発元の資料だけが根拠のものは `documented`、確かめた範囲の外の版は `extrapolated`
  （新しい版は「対応が続いている」、古い版は「対応していない」と見なす）。FIPS 版のように「確かめた範囲では対応していない」ものは、それより新しい版を「不明」とする。
- **開発元の資料で確かめられたもの:** OpenSSL 3.5.0（NEWS.md）、Bouncy Castle 1.79（開発元の発表）、Conscrypt 2.6.0 / 2.7.0（リリースノート）。
  Bouncy Castle のリリースノートの本文と、Netty tcnative のリリースノートは、取得できなかった（後者は、リリースノート自体が公開されていない）。
- **Conscrypt の TLS:** リリースノートによると、X25519MLKEM768 は 2.6.0 で対応、2.7.0 で既定になった。実物では確かめていない（根拠は資料だけ）。

### 段階 2（クラスファイルから暗号 API の参照を拾う）の試算（2026-11-14、検証ラボ）

実装するかどうかを利用者が判断するための試算。結果を見て、実装しないと決まった（設計書の付録 A.2）。

- 方法: 暗号の呼び出しを 15 通りの書き方で並べたテスト用アプリ（Spring Boot 3.5.16 と Bouncy Castle 1.87 を同梱）をラボでビルドし、
  クラスファイルの定数プール（文字列と、メソッド・クラスへの参照の名前）だけを読んだ（`lab/phase2/stage2-scan.py`。コードは実行も逆コンパイルもしない）。
  拾い方は、厳しめ（暗号 API の `getInstance` への参照を持つクラスにある、アルゴリズム名の形をした文字列）と、緩め（どのクラスでも）の 2 通り。
- アプリ自身のコード: 名前を直接書く・定数にする・コンパイル時に連結する・表から引く書き方 11 件は、すべて拾えた。
  名前を実行時に組み立てる書き方 1 件と、設定や環境変数から取る書き方 2 件は拾えない。Bouncy Castle のクラスを直接使う 2 件は、クラスへの参照として拾えた。
  誤って拾ったものは、厳しめで 2 件（使っていない表の値、どこからも呼ばれないコード）、緩めで 7 件（画面の表示用の文字列や選択肢の一覧を含む）。
- 同梱ライブラリ（17,703 クラス）: 厳しめで 70 件、緩めで 795 件（Bouncy Castle だけで 647 件）。アプリが使っているかどうかとは関係がないので、
  対象はアプリ自身のコードに限る必要がある。自社のコードを別の JAR に分けて同梱する作りでは、入れ子の JAR を開かない限り拾えない。
- 限界: テスト用アプリは開発者が書いたもので、実際の業務アプリの標本ではない。割合は「どの書き方が拾えて、どれが拾えないか」を示すもの。

---

## 7. レポートと出力

### レポートの作り直し（2026-11-12、利用者の指摘の反映）

1 ホスト分のレポートを実物で見たうえでの指摘を受けて、次のように変えた。

| 指摘 | 対応 |
|---|---|
| 移動のための欄は横に置く。複数の結果をまとめたときも、横の欄で表示を切り替える | 左に固定の欄を置いた。複数ホストでは「全体の集計」と各ホストを並べ、選ぶと表示が切り替わる（スクリプトは使わず、スタイルシートの `:target` で切り替える） |
| 全システムの集計の画面と、そこから個別の詳細への移動 | `kagiya report A.json B.json ...` で、全体の集計（要点の合計、ホストごとの状況の表）と、ホストごとの詳細（1 ホストのときと同じ内容）を 1 つの HTML にまとめる |
| `/etc/os-release` をスキャンの概要に使う | スキャン時に読み、結果のホスト情報（`meta.host.distribution`）に記録する |
| 「実際に効く値」が分かりにくい | 「このサービスが受け入れる設定になっている方式（設定の記載と既定値から算出）」に言い換えた |
| 量子計算機に弱い方式を括り出し、その中に内訳を出す | 要点を「量子計算機に弱い方式」の合計と、その下の「鍵交換」「署名・認証」の内訳にした。「量子計算機で強度が下がる方式」（AES-128 など）も数える |
| 用語にマウスを載せると説明が出るようにする | 要点の項目と判定のバッジに説明を付けた（スタイルシートだけで表示する） |
| 「参照されていない秘密鍵」は、いないことを証明できない | 「設定からの参照を確認できなかった秘密鍵」に改め、使われていないことを示すものではないこと、この表示だけで削除しないことを明記した |
| 「調べられなかった箇所」は挙げきれない | 「探索した範囲と、読み飛ばしたもの」に改めた。探索の起点を示し、その外は調べていないと明記したうえで、起点の下で読み飛ばしたもの（権限がなく読めなかったものなど）を理由ごとに示す |
| サービスはアコーディオンで畳む。範囲の左の縦線は不要 | すべてのサービスを畳んで示し、縦線をやめた |
| 証明書ストアの「署名 …（106 件）量子計算機に弱い 該当なし」が読めない | 署名の方式ごとに、件数・量子計算機に対する判定・現在の計算機に対する判定を列に分けた表にした。「該当なし」は「指摘なし」に改めた |
| 起動するよう設定されていないサービスも要点に載せる | 見つかったサービスをすべて数える。起動するよう設定されているかどうかは、各サービスの欄に示す |

### テンプレートエンジンを使わない描画への置き換え（2026-11-13）

リリースの手順を作る中で、配布する実体に `syscall.sendto` などの通信用の関数が含まれていることが分かった（CI の「通信・プロセス起動系のシンボルがないこと」の確認に当たる）。
HTML レポートを入れたとき（226bb15）からの退行で、原因は `html/template`（内部の `text/template`）。テンプレートエンジンは名前からメソッドを呼ぶ
（`reflect` の `MethodByName`）ため、リンカが未使用のメソッドを捨てられなくなり、標準ライブラリのファイル記述子の型（`internal/poll.FD`）に付いている
`Accept`、`WriteTo` などが実体に残っていた。`net` パッケージと `socket` / `connect` / `bind` / `listen` は入っておらず、実行される経路もなかったが、
「通信の機能を本体に設けない」ことを機械的に確かめられる状態を保つため、確認を緩めずに原因を取り除いた。

- レポートの HTML は、Go のコードで書き出す（`internal/report/render.go`）。書き出しは 1 つの関数だけを通り、**渡した文字列は必ずエスケープされる**。
  エスケープせずに出るのは、型 `raw` の値（ソースに直接書いた固定の HTML）だけ。値を置くのは、要素の内容と、二重引用符で囲んだ属性値の位置に限る。
  リンクにする URL は、https で、URL に使える文字だけからなるものに限る。
- 置き換えの前後で、出力が同じであることを確かめた（テスト用の結果 4 種と、検証ラボの実物の結果 4 種。空白の違いを除いて一致）。
- 再発防止: `text/template` と `html/template` を、依存に入れてはならないパッケージに加えた。さらに、実際にビルドした実体のシンボルを調べるテスト
  （`TestBinaryHasNoNetworkSymbols`）を足し、CI を待たずに手元のテストで検出できるようにした。

### CBOM（CycloneDX）への変換（2026-11-13、検証ラボ）

`kagiya convert --to cbom RESULT.json` で、結果を CBOM（CycloneDX 1.6 の JSON、`<結果の名前>.cdx.json`）に変換する。
ほかの CBOM 対応のツールに取り込めるようにするためのもので、情報の正本は結果 JSON のまま。

- **版は 1.6 とした。** 仕様は 1.7 系まで出ているが（2026-11-13 時点のタグ: 1.7、1.7.1、1.7.2）、暗号資産の表現は 1.6 で入り、読み手のツールの対応が広いため。
- **項目の名前と取り得る値は、公式のスキーマから確認した。** 出典: `https://github.com/CycloneDX/specification` のタグ 1.7.2
  （コミット 349314a9d7671d7d2ca5b711a725f49a73979da6）の `schema/bom-1.6.schema.json`
  （SHA-256 18f57f7482593bad9f21b4feed09084640cbeff419d62ad5090c5ceccca5b37d）。
- **検証:** 実物の結果 3 件（RHEL 9.9、Debian 13、Ubuntu 24.04。部品は 900 / 382 / 332 個）から作った文書を、このスキーマで検証し、違反は 0 件
  （`lab/phase4/cdx.sh`。Docker 公式の python イメージで jsonschema 4.23.0 を使用）。わざと壊した文書では違反が検出されることも確かめた。

対応づけ:

| kagiya の結果 | CBOM |
|---|---|
| アルゴリズム | 暗号資産（algorithm）。種別、鍵長（`parameterSetIdentifier`）、OID |
| 証明書 | 暗号資産（certificate）。主体者、発行者、有効期間、署名アルゴリズムと公開鍵への参照、指紋、見つかった場所 |
| 秘密鍵・公開鍵 | 暗号資産（related-crypto-material）。種類、アルゴリズムへの参照、鍵長、形式、保護の有無。**値そのものは出さない** |
| キーストア | ファイル（`file`）。形式とエントリの数はプロパティ |
| サービスが受け入れる方式（範囲ごと） | 暗号資産（protocol）。暗号スイートは `cipherSuites`、鍵交換のグループと SSH の方式は、アルゴリズムの資産への参照（`cryptoRefArray`） |
| サービス、プログラム、暗号ライブラリ | `application` / `library` と、依存関係（ホスト → サービス → ライブラリ・プロトコル） |

- 量子計算機に弱いと判定したアルゴリズムには `nistQuantumSecurityLevel: 0` を付ける。それ以外には水準を付けない（このツールは水準を判定していない）。
- 鍵交換のグループと SSH の鍵交換は、判定がハイブリッドなら種別を `combiner`、耐量子なら `kem`、それ以外は `key-agree` とする。
- CycloneDX に対応する欄がない情報（判定、利用の確からしさ、確度、特定できなかった理由、証明書ストアなど）は、名前が `kagiya:` で始まるプロパティに入れる。
- 判定は、結果ファイルの中の判定（スキャンした時点の評価ポリシー）をそのまま使う。HTML レポートのようには判定し直さない（変換は結果だけから決まるようにするため）。
- 文書の通し番号（`serialNumber`）はスキャンの ID から、時刻（`timestamp`）はスキャンの時刻から決める。同じ結果からは、同じ文書ができる。

---

## 8. レビューと調査資料

### レビュー記録（設計段階）

v0.1 に対し独立エージェントによるクリティカルレビューを実施（2026-11-12）。重大 8 件・中 14 件・軽微 10 件の指摘を受け、v0.2 で次のとおり反映した。

| 指摘 | 対応 |
|---|---|
| S-1 実効値解決モデルが現実と合わない | 5.4 を「層ごとの演算の合成＋解決フック＋生の値の保存＋正解データ検証」に改訂。9章 F で相談 |
| S-2 優先度・seccomp がスレッド単位 | 4.2・6章で全スレッド適用と適用後検証を明記。Landlock は v1 から除外 |
| S-3 Windows の「通信コードなし」が記述どおりには成立しない | 4.2 の主張を実測に合わせて修正。`x/sys/windows` は不使用とし自前ラッパ（2.4、Phase 0） |
| S-4 rpm DB が後回し | Phase 1b に前倒し。既定値表のキーにディストリとパッケージリリースを追加（5.3、7.3） |
| S-5 秘密非出力の穴 | 4.5 に未知名・捕捉値の検証、鍵 ID の定義、パーサエラーの扱い、ルールの信頼境界を追記 |
| S-6 ネットワーク FS 回避の穴 | 4.3 をハンドル相対走査に改訂。保証範囲を 4.2 冒頭に定義。実行ファイル自体の所在も検査 |
| S-7 `debug/elf`・`debug/pe` と BER | 2.4・5.7 に上限付き読取と BER 対応を明記 |
| S-8 負荷対策が不十分 | 6章を優先度＋流量制限の併用に改訂。既定値を数値で記載 |
| M-1〜M-14 | 環境変数とコアダンプ（3.2、4.2）、import 単位の静的検査（3.3）、作成時 DACL（4.6）、`maps`/`environ` の利用（5.3）、Windows のプロセス調査をしない（5.3）、Windows ストアの物理位置（5.5）、データモデルの実体追加（7.2）、CBOM 対応（7.2）、評価ポリシー（7.2）、ルール形式（7.3）、.NET メタデータ（5.7）、キーストアのパスワード（9章 A）、フェーズ再編（11章）、終了コード・命名・文字コード（3.2、7.2） |
| 未反映（将来検討） | 国内商用ミドルウェアの初期対応、外部ルールの署名検証、パス・Subject の仮名化オプション |

レビュー後のユーザー相談（9.1）により、レビュー提案から変更した点: M-4（`environ`・`maps` の活用）は「既定で読まない、`environ`・`cmdline` は常に読まない」に、M-12（設定ファイル記載のパスワード利用）は「実装しない」に変更。M-14 の集約（`merge`）は v1 必須に格上げ。

ユーザーコメント（2026-11-12、v0.4 で反映）:

| コメント | 対応 |
|---|---|
| ライブラリ既定値をディストリのパッケージ版ごとに持つ。rpm 読取の前倒し | 7.3 の `libraries/*.yaml` に明記。rpm DB 読取は Phase 1b（v0.2 で前倒し済み） |
| ライブラリ特定（`DT_NEEDED`、版文字列）を Phase 1 に | Phase 1b に明記。Phase 5 はその拡張と位置づけ |
| ソースコード解析に C# を追加（VB.NET と API ルール共有） | 5.6・7.3・Phase 4 に反映。API ルールは `source/dotnet/` に1本化 |
| YAML パーサはエイリアス展開に上限があるものを選ぶ | 7.3 に選定条件として明記。加えてエイリアス自体を拒否し、テストで確認 |

### レビュー指摘への対応（2026-11-12）

実装済みのコードに対する7点の指摘を検討し、次のとおり対応した。

| # | 指摘 | 対応 |
|---|---|---|
| 1 | ハードリンクに失敗すると、書いた結果（`.partial`）を消してしまう。vfat / exfat では必ず失敗する | 採用。ハードリンクが使えなければ「上書きしない改名」（Linux の `renameat2`）で確定する。それも使えなければ `.partial` を残し、その場所をエラーで知らせる。出力先・ログ先で確定できるかを、スキャンの前に試験ファイルで確かめる |
| 2 | seccomp の拒否対象に、マウント操作とカーネルの鍵保管庫の操作を加える | 採用。`mount`、`umount2`、`open_tree`、`move_mount`、`fsopen`、`fsconfig`、`fsmount`、`add_key`、`request_key`、`keyctl` を追加。番号は、既存の分も含めてカーネルのヘッダ（Debian 13 の linux-libc-dev 6.12.116-1、amd64 と arm64）で確認した |
| 3 | 優先度の低下と封じ込めを、`scan` 以外のサブコマンドでも行う | 採用。`convert`、`rules export`、`rules validate` でも最初に適用する |
| 4 | 起点の追加で `os.Lstat` を直接呼んでいる。走査がディレクトリを開くときに、差し替えられたリンクを辿り得る | 前半は採用（safefs を通す形に変更）。後半は、リンクを辿らない方法でディレクトリを開く実装への置き換えを今後の作業とし、現状を限界として記載した |
| 5 | import の検査が、import より後ろの `//go:linkname` を見ていない。アセンブリや `vendor/` も対象にする | 採用。ファイル全体を解析し、アセンブリ・オブジェクトファイルが `internal/platform` 以外にないこと、`vendor/` が `syscall`・`unsafe`・`//go:linkname` を使っていないこと、cgo を使っていないことを検査する |
| 6 | 出力先がグループ書き込み可の場合と、所有者が実行ユーザー・root 以外の場合も拒否する | 採用 |
| 7 | ワークフローのアクションをコミットのハッシュで固定する。`upload-artifact` は 4.4 以上にする | 採用。`actions/checkout` v4.4.0、`actions/setup-go` v5.6.0、`actions/upload-artifact` v4.6.2 のコミットに固定した（ハッシュは GitHub の API で2回取得して一致を確認） |

実物での確認（検証ラボ、RHEL 8.10 と Ubuntu 16.04 のコンテナ）: 拒否対象を追加した seccomp を適用した状態で、スキャン・変換・ルールの書き出しと検証が最後まで動いた。上書きしない改名は、実際のカーネルで「新しい名前への改名は成功、既存の名前への改名は拒否」となることを確認した。

### 別途の調査資料から得た論点（2026-11-12）

対象アプリケーションの候補を広く洗い出した調査資料（157 アプリ、優先度 A が 41、検証ラボに保管。リポジトリには含めない）を確認した。
資料の記述は**仮説**として扱い、ルールの出典にはしない。ルール化するのは、検証ラボの実物で確かめたものだけとする。

資料のうち手元の実物で確かめられた3点は、いずれも実物と整合した。

- OpenSSH の既定の鍵交換: 9.2p1（Debian 12）と 9.6p1（Ubuntu 24.04）は `sntrup761x25519` が先頭、10.0p2（Debian 13）は `mlkem768x25519-sha256` が先頭。
- RHEL 系の Apache httpd の `ssl.conf` は `SSLCipherSuite PROFILE=SYSTEM`（RHEL 8.10 / 9.9 / 10.3）。
- RHEL 系の nginx の設定例は `ssl_ciphers PROFILE=SYSTEM`。

同時に、上流の版だけでは既定値が決まらない実例も得られた: **同じ OpenSSH 9.9p1 でも、RHEL 9.9 の鍵交換は `curve25519-sha256` が先頭で耐量子の方式を含まず、RHEL 10.3 は `mlkem768x25519-sha256` が先頭**（いずれも `sshd -T` の出力）。
既定値表のキーにディストリとパッケージ版を含める方針（7.3）の裏付けになる。

設計に取り込む論点:

| 論点 | 内容 | 扱い |
|---|---|---|
| 既定値の決まり方は3系統 | OpenSSL を使うアプリは OS の暗号ポリシーに従う。Go 製のアプリは Go の標準ライブラリを静的に含み、Go の版で決まる。Java 製のアプリは実行する JDK の設定で決まる。どの系統かを先に判定する必要がある | Go のビルド情報の読み取りと JDK の特定を、Phase 5 から Phase 1c の前に前倒しすることを検討する |
| 通信の方向 | 外向きの接続（メールの送信、SSH クライアント、ログの転送、上流への TLS）も、鍵交換の観点では受信側と同じ重みがある | 設定値と出現に「受信／送信」の方向を持たせる（Phase 1b のアプリ設定の読み取りで入れる） |
| 静的リンクされた暗号ライブラリ | 暗号ライブラリを本体に静的に含むアプリでは、本体に埋め込まれた版文字列が正しい版になる（動的リンクの場合は逆で、本体の文字列は当てにならない） | 暗号ライブラリに動的リンクしていないバイナリに限り、本体の版文字列を採る。Phase 5 |
| 設定がファイルにないアプリ | 鍵や設定をデータベースなどに持つアプリがある | アプリの定義に「ファイル以外に設定がある」と書けるようにし、結果の網羅性の欄に「未確認」と明示する |
| 暗号を使っていない通信 | 既定で暗号化しないプロトコルや設定も、棚卸しの結果として価値がある | 追加開発の候補 |
| 既定のままの証明書・鍵 | 導入時に自動生成された自己署名証明書などが残っている状態を検出する | 追加開発の候補 |
| 前方秘匿性のない鍵輸送 | RSA 鍵交換など、記録された通信が後から解読され得る方式を評価で強調する | Phase 3（評価ポリシー） |
| アプリごとの暗号ライブラリの違い | 同じアプリでも、ディストリによって使う暗号ライブラリが違うことがある | 仮定せず、リンク先の特定（実装済み）の結果から判定する |

資料にある商用ソフトウェア（データベース、アプリケーションサーバー、ファイル転送製品など）は、検証ラボの方針（商用ソフトのイメージは使わない）のもとでは実物で確認できない。
対応する場合は、利用者の環境での確認か、ベンダーの公式文書を出典とする別の手順が要る。

---

### 独立したレビュー（非機能要件: 副作用・セキュリティ・可用性）への対応（2026-11-14）

独立したレビュアーによるレビュー（対象は `93a0368`。ソースを読むだけの方法）の指摘を、現在のコードで確かめたうえで、利用者と対応を決めた。
各修正は、先に失敗するテスト（または、コンテナでの失敗の再現）を置いてから行った。

| 指摘 | 内容 | 対応 |
|---|---|---|
| A-1 | 細工した JAR（中央ディレクトリのヘッダを大量に並べたもの）で、メモリを数 GB 確保させられる | 済。標準の zip の読み取りに渡す前に、ヘッダを自分で数える。実測: 30 万件で 77 MiB を確保していた。直した後は、上限を超えたところで読むのをやめる |
| A-22 | JAR のエントリ名の制御文字・不正な UTF-8 | 済（一覧に入れない） |
| P-1 | キーストアの保護方式の重複の確認が二乗時間 | 済。実測: 30 万件で約 3 分 → すぐ終わる。種類は 64 まで |
| P-2 | 分割された OCTET STRING の入れ子で、入力の何十倍も確保する | 済。実測: 0.6 MB の入力で 121 MB → 1 MB 未満。入れ子は 4 段まで |
| P-4（一部） | `authorized_keys` 類の行分割 | 済。実測: 1 MiB の入力で 25 MB → 1 MB 未満 |
| A-3、A-9 | 中断と時間制限が、探索のフェーズにしか効かない。休止を割り込めない | 済。処理の区切りと、休止の間に確かめる。2 回目のシグナルか 30 秒で強制終了。休止は 1 回 1 秒まで。Ubuntu 24.04 のコンテナで、JAR を開く処理の途中の SIGTERM（すぐ停止）と `--max-duration 3s`（4 秒で終了）を確かめた |
| A-11、A-12 | SIGHUP、ログが書きかけの名前のまま残る | 済（SIGHUP でも結果を書いて終わる。ログは最初から最終名） |
| A-2 | 読んだファイルとディレクトリの atime を書き換える | 済（`O_NOATIME`）。コンテナ（relatime）で、直す前は変わり、直した後は変わらないことを確かめた |
| A-4、A-5（メモリ） | panic の回復、メモリの上限 | レビューの前に実装済み（`c46cd88`） |
| A-6 | 既定の出力先・ログ先 | 済。出力先が起点と重なる場合は断る。ログ先の既定を、出力先の下にした（要件からの変更。利用者と確認） |
| A-8 | 「出力先以外に書かない」の実行時の層と検証 | 済。CI で、変更系の呼び出しの種類と回数、探索した場所がスキャンで変わらないことを確かめる。書き込み系の関数は `internal/output` だけ、という静的検査。seccomp の拒否リストの拡大。Landlock（使えるカーネルでだけ） |
| A-13 | 出力先の権限の付け方 | 済（開いたディレクトリに付ける。上位のディレクトリの権限を確かめる） |
| A-5（残り）、A-7、A-4（残り） | `GOMAXPROCS`、件数の上限、ログの上限、最上位の回復、ファズテストの追加 | 済。同時に使うプロセッサは 2 つまで。資産 50 万件・出現 200 万件まで（超えたら未完了）。読み飛ばしのログは理由ごとに 1,000 件まで、ログ全体は 64 MiB まで。`--max-file-size` は 1024 MiB まで。探索の後のフェーズにも CPU の上限が効く。最上位でも panic を受け止めて、途中の結果を書き出す。ファズテストを 14 個のパーサに追加（各 8 秒回して、問題なし）。結果をストリームで書き出すことは、していない |
| C-1〜C-5 | `report` / `convert` の上限、埋め込みの CBOM の判定、CSV の全角文字など | 済。埋め込みの CBOM は、やり直した判定を使う（入力の判定がそのまま出ることを、テストで再現した）。結果ファイルの件数の上限と負の数を確かめる。重複の確認は map。CSV は全角の ＝ ＋ － ＠ と先頭の空白の後ろも対象（表計算ソフトでの実際の挙動は確かめていない）。スキャン ID の先頭を表示。CSP に `form-action` と `base-uri`。CBOM の参照（`bom-ref`）が重なりうる件は、直していない |
| B-1、B-2、B-4 | sshd の `Match`、java.security の報告、除外したパスの名前 | 済。`Match` の条件は検証を通ったものだけを記録。java.security の報告は定型文。`.conf` の `JAVA_HOME` は、見つかっている JDK を指す場合だけ使う。除外の指定で外したものは、件数だけを数える（名前は、結果にもログにも残さない） |
| A-10 の 1・3、A-20、A-23 | マウント表の読み方、`.zfs`、並びの固定、表示用の文字の無害化 | 済。マウント表は 1 回で読み、2 回続けて同じ内容になるまで読み直す。ZFS の `.zfs` には入らない（実物の ZFS では確かめていない）。OS の設定の並びを固定。レポートでは、制御文字・書字方向を変える文字・幅のない文字を取り除く（結果の JSON と CSV には、そのまま残る） |
| A-15 | 名前で開く経路のハンドル相対化 | 実装しない（利用者が決定。蓋然性が低い） |
| A-17 | Linux 以外での実行 | 現状のまま（警告を記録して続ける） |
| A-18 | 起点が 1 つも読めなかったときの終了コード | 0 のまま（利用者が決定。エラーが起きたわけではないため） |
| A-5 の `oom_score_adj` | メモリ不足のときに先に止められるようにする設定 | 設定しない（利用者が決定） |
| P-3、P-4 の残り、A-10 の 2、A-14、A-16、A-19、A-21、B-3 | root だけが書ける入力、実機での確認が先のもの、実害の小さいもの | 見送り |

確かめる途中で分かったこと:

- kagiya はコアダンプを止めるために自分のメモリを外から読めなくしているので、`strace` にはパスの文字列が見えない（番地だけが出る）。
  「出力先以外に書き込まない」の確認は、呼び出しの種類と回数、スキャンの前後の比較で行う。
- 手元のコンテナ（Docker Desktop、カーネル 7.0）では、seccomp も Landlock も適用できた。

## 9. 進み具合の記録（フェーズごと）

### Phase 0（2026-11-12 時点）

| 項目 | 状態 | 備考 |
|---|---|---|
| 禁止依存の検査（`net`・`os/exec` 等） | 済 | linux/amd64・linux/arm64・windows/amd64 の依存グラフをテストで検査。linux バイナリに通信・exec 系シンボルが無いことも確認 |
| import 規約の検査 | 済 | `os`・`path/filepath` は `cli`/`safefs`/`platform`/`output` のみ、`syscall`・`unsafe` は `platform` のみ。検証ラボのコードの参照も禁止 |
| CLI 骨格 | 済 | `scan`、`rules export`、`rules validate`、`version` |
| `safefs`（Linux） | 済（ラボで確認） | ハンドル相対走査、マウント表による事前判定、デバイス番号の照合、除外、権限エラー記録、差し替え検出。ロジックは単体テスト済み |
| 流量制限 | 済 | CPU 使用率（既定 25%）、読み取り速度（既定 20 MiB/秒） |
| 出力の保護（Linux） | 済 | ディレクトリ 0700、ファイル 0600、上書きなし、リンクを辿らない |
| ログ | 済 | JSON Lines、制御文字のエスケープ |
| ルールローダ・書き出し・検証 | 済 | 厳格な YAML 読み込み（エイリアス禁止、上限）、外部ルールディレクトリの信頼性検査 |
| 縦切り（証明書 → 結果 JSON） | 済 | PEM / DER の X.509 証明書。自前の DER リーダ（ファジング実施） |
| 優先度低下・コアダンプ無効化・seccomp（Linux） | 済（arm64 はラボ、amd64 は CI で確認） | arm64 では全スレッド nice 19、`Seccomp: 2` を確認。amd64 は手元のエミュレーション（Rosetta 2）では seccomp を適用できないため、GitHub Actions の amd64 ランナー（実カーネル）で `ci/verify-linux.sh` により確認 |
| 最小対応 OS での起動検証 | 一部済 | Ubuntu 16.04 / 24.04、UBI 8 / 9 のコンテナで動作。ただしカーネルは Docker の VM のもの（7.0）で、各ディストリ本来のカーネルではない |
| 通信なしの結合テスト（strace） | 済（arm64 / amd64） | ラボの4イメージ（arm64）と CI のランナー（amd64 / arm64）で通信・プロセス起動系システムコール 0 回 |
| 負荷試験による既定値の確定 | 未 | 同上 |
| Windows（API ラッパ、DACL、優先度、Job、プレースホルダ回避） | **未着手** | Windows ではビルドは通るが、出力の保護を保証できないため書き込みを拒否する（`scan` は動作しない）。実機の検証環境が必要 |
| `--dry-run`、`--rules-mode overlay`、`--workers`、`host.id`、`O_NOATIME` | 未 | Phase 1a 以降で実装 |
| ファイルシステム種別の分類表をルールに外出し | 未 | 現在はコード内の表（`safefs.DefaultPolicy`） |

### Phase 1a（2026-11-12 時点）

| 項目 | 状態 | 備考 |
|---|---|---|
| ASN.1 リーダの BER 対応 | 済 | 不定長形式、分割された OCTET STRING。入れ子の深さに上限 |
| X.509 証明書、CSR | 済 | `TRUSTED CERTIFICATE`（OpenSSL の信頼設定付き）、PKCS#7 の証明書束（PEM / DER）を含む |
| 秘密鍵・公開鍵 | 済 | PKCS#1、PKCS#8（暗号化の保護方式を含む）、SEC1、DSA 従来形式、SPKI、OpenSSH 秘密鍵、SSH 公開鍵（`*.pub`、`authorized_keys`、`known_hosts`） |
| キーストア | 済 | PKCS#12（完全性保護、区画ごとの暗号化方式、鍵の保護方式、平文の証明書）、JKS、JCEKS（証明書と鍵の保護方式）。パスワードは使わない |
| 結果 JSON への反映 | 済 | 資産の型に `private-key`、`public-key`、`csr`、`keystore` を追加。形式・暗号化の有無・保護方式は出現ごとの `detail` に持つ |
| 鍵の対応付け | 済 | 公開鍵の指紋（SubjectPublicKeyInfo の SHA-256）で、同じ鍵の異なる形式、証明書、SSH 鍵を1つにまとめる。公開成分が得られない鍵（暗号化された鍵、公開鍵を含まない形式）は場所から ID を作る |
| 暗号カタログの拡充 | 済（一部） | 鍵・キーストアの保護方式（PBES2、PBKDF2、HMAC、AES、3DES、PKCS#12 PBE、bcrypt、Java キーストア固有の方式）、SSH の鍵種別名・暗号名 |
| CSV 出力 | 済 | `kagiya convert --to csv`。出現1件1行、既定で UTF-8 BOM 付き、数式として解釈される先頭文字の無害化 |
| テスト | 済 | 実物のツール（OpenSSL 3.5.7、OpenSSH 10.0p2、keytool / Temurin 21.0.13）で生成したファイルと、ツール自身が報告した値との照合。各パーサのファジング |
| Linux の証明書ストアの位置づけ | 済 | `rules/os/stores.yaml`（出典必須。出典のない定義は読み込み時に拒否）。ストア内で見つかった出現には `store` が付き、既定の探索起点に含まれないストアの場所は起点に追加される。UBI 8 / 9 と Ubuntu 16.04 の実物で確認 |
| PGP 鍵、PuTTY PPK、NSS DB、BKS | 未 | Phase 6 |

実装して分かったこと・決めたこと:

- 出現の `state` に `present`（ファイルとして存在する。用途は未特定）を追加した。設定ファイルの解析（Phase 1b 以降）で用途が分かれば `configured` などになる。
- 秘密鍵は拡張子なしで置かれることが多い（`id_ed25519`、`ssh_host_rsa_key` など）ため、拡張子のない 16 KiB 以下のファイルは中身が PEM かどうかを見る。読み取り量が増える点は流量制限で抑える。
- キーストアの別名（エントリ名）は出力しない。
- `openssl pkey -outform DER`（OpenSSL 3.5.7）は PKCS#8 ではなく従来形式（PKCS#1）を出力する。構造から形式を判定するため正しく `pkcs1` と記録される。
- JKS / JCEKS の鍵保護方式の OID（`1.3.6.1.4.1.42.2.17.1.1`、`1.3.6.1.4.1.42.2.19.1`）は、keytool が生成した実物から読み取って確認した。
- PKCS#8 の DSA 鍵と Ed25519 鍵（OpenSSL が出力する形式）は公開成分を含まないため、公開鍵の指紋は得られない（秘密成分からの計算は行わない方針のため）。

### Phase 1b（2026-11-12 時点）

| 項目 | 状態 | 備考 |
|---|---|---|
| パッケージ版の特定（rpm、dpkg） | 済 | rpm データベースは Berkeley DB（RHEL 8 系）と SQLite（RHEL 9 系以降）の両方をファイル形式から直接読む。SQLite は先行書き込みログ（WAL）の確定済みの内容を反映する。dpkg は状態ファイルを読む。コマンドは実行しない |
| 記録対象パッケージのルール | 済 | `rules/os/packages.yaml`（出典必須）。暗号ライブラリ、SSH、Web サーバー、暗号ポリシー、信頼ストアのパッケージだけを結果に記録し、それ以外は総数のみ |
| 決まった場所のファイルを安全に開く仕組み | 済 | `safefs.Opener`。走査と同じ規則（触れる前のマウント表判定、リンクを辿らない、通常ファイルのみ）。大きなデータベースを全部読み込まずに必要な部分だけ読む |
| リンクしている暗号ライブラリの特定（`DT_NEEDED`、版文字列） | 済 | ELF の動的セクションと `/etc/ld.so.cache` を直接読み、動的リンカと同じ順序（RPATH、RUNPATH、キャッシュ、既定のディレクトリ）で実体を特定する。版はライブラリ本体の版文字列から読む。アプリとライブラリの定義は `rules/apps/`、`rules/libraries/`（出典必須）。結果 JSON の `components` に記録 |
| OS 暗号設定（暗号ポリシー、OpenSSL 設定など） | 済（一部） | システム全体の暗号ポリシー（選択されたポリシー名と適用済みのポリシー名）、カーネルの FIPS モード、OpenSSL のシステム既定の TLS 設定（設定ファイルの `.include` を辿って読む）。結果 JSON の `os_settings` に、値とその出どころ（ファイルと行）を記録する。GnuTLS、NSS、Kerberos、Java などは未対応 |
| アプリの設定値と利用の確からしさ（OpenSSH） | 済 | sshd の設定ファイル（Include、Match を含む）と、systemd のユニット・環境ファイルから渡される起動引数を読み、明記された暗号関連の値を出どころとともに記録する。サービスの有効化状態（systemd の `*.wants` のリンク、マスク）から利用の確からしさを決め、設定から参照されている鍵にも付ける。通信の方向（受信／送信）を記録する。結果 JSON の `services`、`settings`、出現の `activity` |
| nginx / Apache httpd の設定値 | 済 | nginx はブロックの入れ子と include、Apache はセクション・Include / IncludeOptional・`<IfModule>` の条件を辿り、明記された TLS 関連の値を、書かれている範囲（http 全体、どの server / VirtualHost）と通信の方向（受信／上流への送信）とともに記録する。Apache は TLS のモジュールが読み込まれているかも見る |

パッケージ読み取りの実物確認（検証ラボ、arm64）: 各コンテナに OpenSSL・OpenSSH・nginx・Apache httpd を導入し、kagiya の結果を `rpm -qa` / `dpkg-query` の出力と突き合わせた。

| イメージ | データベース | 導入済みの総数（kagiya / 正解） | 記録したパッケージ | 版の不一致 |
|---|---|---|---|---|
| RHEL 8.10（`redhat/ubi8@sha256:44f19e30…`） | rpm（Berkeley DB） | 271 / 271 | 12 | 0 |
| RHEL 9.9（`redhat/ubi9@sha256:8b212f75…`） | rpm（SQLite） | 211 / 211 | 14 | 0 |
| Ubuntu 16.04.7（`ubuntu@sha256:1f1a2d56…`） | dpkg | 171 / 171 | 10 | 0 |
| Ubuntu 24.04.5（`ubuntu@sha256:2198e4c6…`） | dpkg | 145 / 145 | 9 | 0 |

テストデータ（`internal/parse/pkgdb/testdata/`）は、実物の rpm / dpkg が作った小さなデータベースと、同じコマンドが報告した一覧の対。
WAL については、変更が本体ファイルに未反映の状態を実物の `sqlite3` で作り、本体だけを読むと古い内容（4件）、WAL を合わせると正しい内容（3件）になることをテストしている。

### Phase 1c（2026-11-12 時点）

| 項目 | 状態 | 備考 |
|---|---|---|
| 実効値の解決の枠組み | 済 | 結果 JSON の `effective_values`。項目ごとに、実際に効く値と、どの層の値からどう求めたか（過程）を記録する。求められない場合は「不明」と理由を残す |
| パッケージ版ごとの既定値表 | 済（sshd） | `rules/defaults/openssh.yaml`（出典必須）。8ディストリのパッケージ版について、空の設定で sshd 自身に報告させた値から生成した。実測した版そのものの表がなければ、パッケージ名・上流の版・ディストリの系列が同じ実測版の表で補間する（確度を一段下げ、注記を残す。2026-11-12 決定） |
| sshd の実効値 | 済 | 明記された一覧（置き換え）、「+追加」「-削除」「^先頭へ」（既定の一覧の加工）、記載なし（既定）。起動引数で渡るポリシー、設定ファイルとして取り込まれるポリシーを含む |
| 正解データとの突き合わせ（sshd） | 済 | 下表 |
| OpenSSL の暗号文字列の展開 | 済 | `internal/tlsciphers`。`HIGH:!aNULL`、`@STRENGTH`、`@SECLEVEL`、`DEFAULT`、`PROFILE=SYSTEM` などを、上流の `ssl/ssl_ciph.c` と同じ手順で展開する。語とスイートの対応・並び・強度・既定・セキュリティレベルは、パッケージ版ごとの対応表（`rules/ciphers/openssl.yaml`、出典必須）から引く |
| OpenSSL を使うサーバーの実効スイート | 済 | `internal/tlseffective`（アプリによらない共通部品）。展開 → セキュリティレベル → 証明書の種類 → DH パラメータの有無の順に絞り込む |
| nginx・Apache の暗号スイートの実効値 | 済 | TLS を待ち受ける server / VirtualHost ごとに求める。外側の階層からの引き継ぎと上書き、アプリの既定の暗号文字列（`rules/defaults/nginx.yaml`、`httpd.yaml`）を含む |
| 正解データとの突き合わせ（nginx・Apache） | 済 | 下記 |
| nginx・Apache のプロトコルの実効値 | 未 | どのプロトコルが通るかは、ライブラリの版・セキュリティレベル・証明書の種類・スイートの組み合わせで決まる（下記の訂正を参照）。測り方から設計し直す |

sshd の実効値の実物確認（検証ラボ、arm64）: 8ディストリ × 3場面で、kagiya が求めた実効値を、同じ環境の sshd 自身が報告した値（`sshd -T`。RHEL 8.10 は systemd と同じ起動引数を付けて実行）と突き合わせた。

| イメージ | パッケージ版 | 導入直後 | 既定の一覧を加工 | 一覧を明記 |
|---|---|---|---|---|
| RHEL 8.10 | openssh-server 8.0p1-34.el8_10 | 8 / 8 | 8 / 8 | 8 / 8 |
| RHEL 9.9 | 9.9p1-16.el9_9 | 9 / 9 | 9 / 9 | 9 / 9 |
| RHEL 10.3 | 9.9p1-33.el10_3 | 9 / 9 | 9 / 9 | 9 / 9 |
| Ubuntu 16.04.7 | 1:7.2p2-4ubuntu2.10 | 6 / 6 | 6 / 6 | 6 / 6 |
| Ubuntu 20.04.6 | 1:8.2p1-4ubuntu0.13 | 8 / 8 | 8 / 8 | 8 / 8 |
| Ubuntu 22.04.5 | 1:8.9p1-3ubuntu0.18 | 8 / 8 | 8 / 8 | 8 / 8 |
| Ubuntu 24.04.5 | 1:9.6p1-3ubuntu13.20 | 9 / 9 | 9 / 9 | 9 / 9 |
| Debian 13 | 1:10.0p1-7+deb13u4 | 9 / 9 | 9 / 9 | 9 / 9 |

合計 198 項目すべてが一致した（イメージのダイジェストは `rules/defaults/openssh.yaml` に記載）。

- 「既定の一覧を加工」の場面では、設定ファイルの先頭に `KexAlgorithms +...`、`Ciphers -...`、`MACs ^...`、`HostKeyAlgorithms -ssh-rsa*,ecdsa-*`（ワイルドカード）を置いた。
  その版の sshd が受け付ける書き方だけを使っている（Ubuntu 16.04 の 7.2p2 は「+」のみ、RHEL 8.10 の 8.0p1 は「+」と「-」）。
- 「導入直後」の場面のうち、設定に記載のない項目の一致は、同じイメージから採取した既定値表を引いた結果なので、表の引き当て（パッケージ版の特定と照合）が正しいことの確認にとどまる。
  解決の規則そのものの確認になっているのは、ポリシーによる置き換え（RHEL）と、加工・明記の場面。

分かったこと:

- **RHEL 9.9 の sshd は、既定では耐量子の鍵交換（`sntrup761x25519-sha512`、`mlkem768x25519-sha256`）に対応しているが、システム全体の暗号ポリシー（DEFAULT）が一覧を明記するため、実際には使われない。**
  版や既定値だけを見ると「対応済み」に見え、実効値を見ると「使われていない」と分かる例。
- **RHEL 9.9 で設定ファイルの先頭に `KexAlgorithms +...` と書くと、加工の対象はポリシーの一覧ではなく sshd の既定の一覧になる**（sshd は最初に得た値を使い、加工は既定に対して行うため）。ポリシーで絞ったつもりの一覧が、意図せず既定の広い一覧に戻る。
- **RHEL 8.10 では、設定ファイルに何を書いても起動引数のポリシーが優先される**（3場面とも実効値はポリシーの値）。

### Phase 3（2026-11-12 時点）

| 項目 | 状態 | 備考 |
|---|---|---|
| 評価ポリシー | 済 | `rules/policies/default.yaml`。量子計算機に対する評価と、現在の計算機に対する評価の2軸。規則ごとに根拠の文書が必須（ないと読み込み時に拒否） |
| 評価の実行 | 済 | `internal/assess`。アルゴリズム・証明書・鍵・TLS の暗号スイート・SSH の方式・TLS のプロトコルの版。スキャン結果に `assessment`（スキャン時点の参考値）を付ける |
| HTML レポート（1ホスト） | 済 | `kagiya report RESULT.json`。外部の資源を読まない単一の HTML（スクリプトなし、スタイルは埋め込み、CSP あり）。評価はレポートを作る時点のルールでやり直す |
| 集約（`merge`）と多数ホストの表示 | 未 | |
| CBOM への変換 | 未 | |
| スキーマの v1 固定 | 未 | |

評価の根拠にした文書（いずれも検証ラボのコンテナ内で取得し、本文を確認した。文書そのものはリポジトリに入れていない）:

| 文書 | 確認した内容 |
|---|---|
| NIST IR 8547（2026年10月 確定版） | 表2・表4（量子計算機に弱い署名・鍵共有と、2030 年より後は非推奨・2035 年より後は不可の期限）、表3・表5（耐量子の方式）、4.1.3 と表6〜8（共通鍵暗号・ハッシュ関数） |
| CRYPTREC LS-0001-2022R2（最終更新 令和8年3月30日） | 電子政府推奨暗号リストの表1（現行暗号）と表2（耐量子計算機暗号リスト）、運用監視暗号リスト |
| CRYPTREC LS-0003-2022R1 | 表2〜表4（鍵長・方式とセキュリティ強度の対応）、表5（強度ごとの利用期間） |
| RFC 8996、RFC 9142 | TLS 1.0 / 1.1 の廃止、SSH の鍵交換方式の推奨 |

評価で決めたこと:

- **AES-128 と SHA-256 は「量子計算機で強度が下がる（reduced）」とする（2026-11-12 決定）。** NIST IR 8547 は AES-128 を耐量子のカテゴリ 1 として置き換えを求めていないが、
  CRYPTREC の耐量子計算機暗号リストに載っている共通鍵暗号は AES-192 / AES-256、ハッシュ関数は SHA-384 以上だけである。国内での利用を主に想定し、CRYPTREC に合わせて区別する。
  規則の説明には、NIST の扱いも併記している。
- **鍵共有を署名より優先して示す。** 鍵共有が量子計算機に弱いと、いま記録された通信が将来解読され得る（harvest now, decrypt later）。レポートの要点では、鍵共有と、それ以外（署名など）を分けて数える。
- **参照した文書に記載のないものは「判定できない」とする。** ARIA・SEED・IDEA、UMAC、bcrypt などは、良いとも悪いとも判定しない。
- **TLS 1.3 のスイートは、量子計算機に対する評価を「判定できない」とする。** 鍵共有がスイートではなく鍵交換のグループで決まるため（グループは別の項目として実効値を求め、そちらで判定する。後述）。

レポートの構成（1ホスト）: スキャンの概要、要点（起動するよう設定されたサービスの設定、ファイルとして見つかった証明書・鍵、調べられた範囲）、
サービスの設定（範囲ごとの実効値と求め方、判定、設定の記載）、証明書と鍵（参照されていない秘密鍵を別枠に、証明書ストアは畳んで署名の方式ごとにまとめる）、
OS とライブラリ、調べられなかった範囲、このレポートでは分からないこと、判定の基準と出典。
起動するよう設定されていないサービスと証明書ストアは畳み、件数を見出しに出す（設計書の 11 章の決定のとおり）。
