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

ライセンス: OpenSSH の設定ファイルとユニットファイルは openssh パッケージ（BSD ライセンス）、暗号ポリシーの生成物は crypto-policies パッケージ（LGPL-2.1-or-later）に由来する。
