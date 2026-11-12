# OS 暗号設定のテストデータ

実物の設定ファイルからの**必要最小限の抜粋**。各イメージに openssl を導入した状態のファイルから、
OpenSSL がシステム既定の TLS 設定を読み込む経路に関係する行だけを抜き出した。

| ディレクトリ | イメージ | 内容 |
|---|---|---|
| `rhel8/` | `redhat/ubi8@sha256:44f19e308462e9152cb26d641fc0ce5bf6cbdab3cd101367aed67573eb2cf20e`（RHEL 8.10） | `/etc/pki/tls/openssl.cnf` の 25〜40 行目、`/etc/crypto-policies/` の `config`・`state/current`・`back-ends/opensslcnf.config`（全体） |
| `rhel9/` | `redhat/ubi9@sha256:8b212f75a0e5a156ac28b1c5c030d2e8a07715254e19d522286118279399af81`（RHEL 9.9） | `/etc/pki/tls/openssl.cnf` の 12〜24 行目と 45〜86 行目、`/etc/crypto-policies/` の同じ3ファイル |
| `ubuntu2404/` | `ubuntu@sha256:2198e4c65076e9cb0b3d695219df667c0e3b0072da64ca3c2648aca17dcecaf5`（Ubuntu 24.04.5） | `/etc/ssl/openssl.cnf` の 10〜20 行目と 50〜75 行目 |
| `ubuntu1604/` | `ubuntu@sha256:1f1a2d56de1d604801a9671f301190704c25d604a416f59e03c04f5c6ffee0d6`（Ubuntu 16.04.7） | `/etc/ssl/openssl.cnf` の 1〜30 行目 |

パッケージとライセンス: `openssl.cnf` は openssl パッケージ（RHEL: openssl-libs、Ubuntu: openssl）の設定ファイルで、OpenSSL のライセンス（1.x は OpenSSL License、3.x は Apache-2.0）に従う。
`/etc/crypto-policies/` 配下は crypto-policies パッケージ（LGPL-2.1-or-later）が生成したファイル。

実物では `back-ends/*.config` は `/usr/share/crypto-policies/<ポリシー名>/` 配下へのシンボリックリンクだが、ここでは通常のファイルとして置いている。
