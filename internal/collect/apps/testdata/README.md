# アプリケーション設定のテストデータ

実物の設定ファイルからの**必要最小限の抜粋**。各イメージに openssh-server を導入した状態から採取した。

| ディレクトリ | イメージ |
|---|---|
| `rhel8/` | `redhat/ubi8@sha256:44f19e308462e9152cb26d641fc0ce5bf6cbdab3cd101367aed67573eb2cf20e`（RHEL 8.10、openssh-server 8.0p1-34.el8_10） |
| `rhel9/` | `redhat/ubi9@sha256:8b212f75a0e5a156ac28b1c5c030d2e8a07715254e19d522286118279399af81`（RHEL 9.9、openssh-server 9.9p1-16.el9_9） |
| `ubuntu2404/` | `ubuntu@sha256:2198e4c65076e9cb0b3d695219df667c0e3b0072da64ca3c2648aca17dcecaf5`（Ubuntu 24.04.5、openssh-server 1:9.6p1-3ubuntu13.20） |
| `ubuntu1604/` | `ubuntu@sha256:1f1a2d56de1d604801a9671f301190704c25d604a416f59e03c04f5c6ffee0d6`（Ubuntu 16.04.7、openssh-server 1:7.2p2-4ubuntu2.10） |

内容:

- `etc/ssh/sshd_config`、`etc/default/ssh`: コメント行と空行を除いた行だけ（そのため行番号は実物と異なる）
- `etc/ssh/sshd_config.d/50-redhat.conf`、`etc/sysconfig/sshd`、systemd のユニットファイル: 全体（いずれも短い）
- `etc/crypto-policies/back-ends/opensshserver.config`: 暗号ポリシー（DEFAULT）が生成したファイルの全体

サービスの有効化を表すリンク（`/etc/systemd/system/*.wants/` 配下）は、テストコードの中で実物と同じ形に作る。

nginx と Apache httpd の設定（`rhel9/etc/nginx`、`rhel9/etc/httpd`、`ubuntu2404/etc/nginx`、`ubuntu2404/etc/apache2`）は、
GitHub Actions で採取した amd64 の実物（RHEL 9.9 は nginx 1.20.1-32.el9_9.1 と httpd 2.4.62-13.el9_8.9、
Ubuntu 24.04.5 は nginx 1.24.0-2ubuntu7.19 と apache2 2.4.58-1ubuntu8.18。イメージのダイジェストは上の表と同じ）から、次のように抜き出した。

- `nginx.conf`、`sites-available/default`、`conf.d/ssl.conf`、`mods-available/ssl.conf`、`ssl.load`、`sites-available/default-ssl.conf`、`ports.conf`: コメント行と空行を除いた行
- `httpd.conf`、`apache2.conf`: ServerRoot、Listen、Include、IncludeOptional の行だけ
- `conf.modules.d/00-ssl.conf`: 全体（1行）

Debian 系で設定を有効にするリンク（`mods-enabled/`、`sites-enabled/`）は、テストコードの中で作る。

ライセンス: nginx の設定ファイルは nginx パッケージ（BSD-2-Clause）、Apache httpd の設定ファイルは httpd / apache2 パッケージ（Apache-2.0）に由来する。OpenSSH の設定ファイルとユニットファイルは openssh パッケージ（BSD ライセンス）、暗号ポリシーの生成物は crypto-policies パッケージ（LGPL-2.1-or-later）に由来する。

`java/alma9-java.config`、`java/alma10-java.config` は、暗号ポリシー（DEFAULT）が生成した Java 用のファイル
（`/etc/crypto-policies/back-ends/java.config`）から、TLS に関係する 3 行（`jdk.tls.disabledAlgorithms`、`jdk.disabled.namedCurves`、
`jdk.tls.legacyAlgorithms`）だけを抜き出したもの。AlmaLinux 9.8（`almalinux@sha256:245f8aab832fe800aa42bdab5fad75ebbd8e0b4c9f24820a83c638b177857ae2`、
crypto-policies 20260224-1.gitea0f072.el9_8）と AlmaLinux 10.2（`almalinux@sha256:5a4b41a427c9717be8f4ac2a32aa22efbae5f9124fbcb79a6765394f312acfe8`）で採取した。
crypto-policies パッケージ（LGPL-2.1-or-later）に由来する。java.security は、テストコードの中に、関係する行だけを書いている。
