# kagiya 設計書（クリプトインベントリ作成ツール）

- 版: 0.4（クリティカルレビュー、ユーザー相談結果、ユーザーコメントを反映。記録は 9章・12章）
- 日付: 2026-11-12
- 要件原文: [requirements.md](./requirements.md)
- ツール名（仮）: `kagiya`（鍵屋）

---

## 1. 目的と位置づけ

### 1.1 目的

ツールが稼働するホスト1台の中にある「暗号の利用実態」を、**読み取りのみ・通信なし**で棚卸しし、
機械可読なインベントリ（独自JSON → CBOM / CSV）と、人が読むHTMLレポートを出力する。

PQC移行の初手として使えるだけでなく、将来の危殆化（例: あるハッシュ関数の破綻）が起きたときに
「どのホストのどこでそのアルゴリズムを使っているか」を即答できる台帳を継続的に維持できることを狙う。
そのため量子脆弱なアルゴリズム（RSA, ECDH 等）だけでなく、AES・SHA-2・HMAC 等も区別なく記録する。

### 1.2 既存ツールが苦手な領域（本ツールの差別化点）

| 領域 | 本ツールの方針 |
|---|---|
| 「実効値」の解決 | 設定ファイルに書かれた値だけでなく、未記載項目を「アプリ設定 ＞ OS暗号ポリシー ＞ ライブラリ既定」の順で解決し、**どの層に由来する値か**を記録する |
| レガシー／運用系言語 | Java に加え VB.NET、C#、PowerShell、シェルスクリプトと、その周辺設定ファイル |
| Windows の OS 設定 | Schannel・.NET・証明書ストア等をレジストリから直接読む |
| アプリ固有ストア | Java キーストア、NSS DB、アプリ同梱 CA バンドル等 |
| ソースのないバイナリ | ELF/PE/class の表層情報（逆アセンブルなし） |
| 閉域・本番環境 | 通信コードを持たない単一バイナリ、低負荷、書き込み先限定 |
| 日本語環境 | Shift_JIS / EUC-JP のソース・設定、日本語レポート、CRYPTREC 暗号リスト上の位置づけ |

### 1.3 非目標（やらないこと）

- ネットワーク越しの調査全般（ポートスキャン、TLS ハンドシェイクによる実測、リモートホスト調査）
- クラウド事業者の管理面（KMS、証明書マネージャ、ロードバランサ設定等）の調査
- 外部コマンドの実行（`nginx -V`、`openssl version`、`rpm -q` 等も実行しない。理由は 5.3）
- ELF/PE の逆アセンブル・逆コンパイル、ソースコードの深いデータフロー解析
- 脆弱性（CVE）スキャン、シークレットスキャン（ハードコード鍵の「存在」は記録するが網羅は目標外）
- 設定の変更・修復、移行の自動実行
- 複数ホストの集中管理サーバ／エージェント常駐（結果ファイルを持ち寄ってレポート化する運用とする）
- v1 では対象外: コンテナイメージ層（`/var/lib/docker` 等。ホストからは既定で除外し記録。コンテナ内で本ツールを実行することは可能）、
  他ユーザーの未ロードのレジストリハイブ、HSM/TPM 内部の鍵、メモリ上の鍵

---

## 2. 言語の選定

### 2.1 結論: Go（`CGO_ENABLED=0` の純 Go 静的リンク）

### 2.2 選定理由

| 観点 | Go の評価 |
|---|---|
| 単一実行ファイル・ランタイム不要 | 純 Go 静的バイナリ。libc に依存しないため glibc の版差（Ubuntu 16.04 の 2.23 ～ 最新）を気にしなくてよい |
| クロスビルド | `GOOS/GOARCH` 指定だけで linux/amd64, linux/arm64, windows/amd64 を生成できる |
| 標準ライブラリで足りる範囲 | `debug/elf`, `debug/pe`, `debug/buildinfo`, `archive/zip`, `encoding/asn1`, `encoding/pem`, `encoding/xml`, `html/template`, `embed`, `regexp`。サードパーティ依存を最小化でき、サプライチェーンリスクと監査コストが小さい |
| 通信しないことの検証可能性 | 依存パッケージグラフから `net`（ソケット実装）と `os/exec` を**排除してビルドできる**。「バイナリに通信コードが存在しない」ことを CI で機械的に検査できる（4.2） |
| 暗黙の通信の排除 | cgo を使わないため glibc の NSS（LDAP/SSSD 等への問い合わせ）を経由しない |
| 悪意ある入力への耐性 | メモリ安全。`regexp` は RE2 系で線形時間（ユーザー定義ルールでも ReDoS が起きない）。`encoding/xml` は DTD・外部実体を解決しない。ただし `debug/elf`・`debug/pe` は敵対的入力への堅牢性が保証されていない（2.4） |
| 監査しやすさ | 導入企業のセキュリティ部門がソースを読む場面を想定。言語仕様が小さく読みやすい |

### 2.3 他候補を採らなかった理由

- **Rust**: 安全性・単一バイナリは同等以上。ただし ELF/PE/ZIP/ASN.1/テンプレート等をクレートに頼ることになり、依存の監査コストが増える。次点。
- **C/C++**: 信頼できない入力（任意のファイル）を大量にパースするツールでメモリ安全でない言語は不適。
- **Python / Java / .NET / Node.js**: ランタイムが必要、またはランタイム同梱で巨大化・起動時展開（＝出力先以外への書き込み）が発生する。
- **PowerShell / シェル**: OS ごとに別実装となり、バイナリ解析等が困難。

### 2.4 Go 採用に伴う弱点と対策

- `crypto/x509` は `net` を import し、未知アルゴリズムや不正気味の証明書に厳格。→ **使用しない**。証明書・鍵は自前の ASN.1 リーダで読む（OID をルール側の表で解決するので、新アルゴリズム追加がルール変更で済む利点もある）。
  PKCS#12 や PKCS#7 は BER（不定長）で書かれることが多く、標準の `encoding/asn1` は BER を拒否するため、リーダは **BER 対応**とする。自作するパーサの量は小さくない（11章のリスク）。
- `golang.org/x/sys/windows`（レジストリ含む）は `net` を import する（実測で確認）。→ **使用しない**。Windows API は標準 `syscall` 上の自前ラッパを `internal/platform` に書く。
  DLL は System32 からのみロードする指定（`LOAD_LIBRARY_SEARCH_SYSTEM32`）で読み込み、DLL 植え付けを防ぐ。
- `debug/elf`・`debug/pe` は公式に「敵対的入力に対して堅牢化されていない」とされ、巨大なメモリ確保があり得る（panic は回復できるがメモリ圧迫は回復できない）。
  → ヘッダのセクション数・サイズを事前検証してから渡すか、必要部分だけ読む上限付きの自前リーダにする（Phase 5 で決定）。
- `os/user` は Windows でドメインコントローラへの問い合わせを起こし得る。→ **使用しない**。UID / SID は数値・文字列のまま出力する。
- 優先度・seccomp 等はスレッド単位の属性で、Go は起動時から複数スレッドを持つ。→ 全スレッド適用の仕組みを使い、適用結果を検証する（4.2、6章）。
- ガベージコレクションとコピーのため、メモリ上の秘密のゼロクリアは保証できない。→ 秘密鍵ファイルは必要最小部分だけ読む方針で補う。
- Go 製バイナリはアンチウイルスに誤検知されやすい傾向がある。→ 最初の配布から署名し、ハッシュを公開する。
- Go の最小対応 OS（Go 1.27 は Wiki 上 Windows 10 / Server 2016、Linux カーネル 3.2）は **Phase 0 に実機／実イメージで検証**する。
- 外部依存は次に限定し、`vendor/` に固定する: `golang.org/x/sys/unix`、`golang.org/x/text`（Shift_JIS/EUC-JP/UTF-16 デコード）、保守されている YAML パーサ1つ（選定条件は 7.3）。CI は `-mod=vendor`・`GOPROXY=off` でビルドする。

---

## 3. 全体構成

### 3.1 実行形態

- 単一プロセス・単一バイナリ。常駐しない。プロセス間通信・子プロセス起動なし。
- 処理はプロセス内のパイプライン。並行度は既定で小さく固定（6章）。

```
            ┌──────────── kagiya (単一プロセス) ────────────┐
 ルール      │  rules ローダ（内包 or --rules 指定ディレクトリ） │
 (内包/外部) ─▶│        │                                      │
            │        ▼                                      │
 ローカル    │  collectors ──▶ 正規化(catalog) ──▶ 重複統合 ──▶ writer ──▶ 出力ディレクトリ
 ファイル/   │   ├ os-policy      ▲                              │      (JSON / CBOM / CSV)
 レジストリ ─▶│   ├ apps ─────▶ resolver(実効値解決)             └──▶ ログディレクトリ
 (safefs経由) │   ├ certstores                                   │
            │   ├ fs-crawl (証明書/鍵/キーストア/バイナリ)        │
            │   ├ source                                        │
            │   └ binary                                        │
            └───────────────────────────────────────────────┘
```

### 3.2 サブコマンド

| コマンド | 役割 |
|---|---|
| `kagiya scan` | ホストをスキャンし結果 JSON（＋任意で CBOM/CSV）を出力 |
| `kagiya convert` | 結果 JSON を CBOM / CSV に変換 |
| `kagiya report` | 結果 JSON（1個以上）または集約 JSON から単一 HTML を生成 |
| `kagiya merge` | 多数の結果 JSON を1つの集約 JSON にまとめる（数百〜数千ホスト向け。7.4） |
| `kagiya rules export` | 内包ルールを指定ディレクトリに書き出す |
| `kagiya rules validate` | ルールディレクトリの構文・整合性を検証 |
| `kagiya version` | ツール版・内包ルール版・ビルド情報を表示 |

主なオプション（`scan`）:

```
--output-dir DIR        結果の出力先（既定: カレントディレクトリ）
--log-dir DIR           ログ出力先（既定: ./logs）
--roots PATH,...        ファイルシステム探索の起点（既定は 5.5 の既定リスト）
--source-dir PATH,...   ソースコード解析対象（指定時のみ解析）
--exclude GLOB,...      除外パス（複数可）  --exclude-from FILE で一括指定
--collectors LIST       実行するコレクタの選択（既定: source 以外すべて）
--rules DIR             外部ルールディレクトリ（指定時のみ読み込む）
--format json,cbom,csv  追加出力形式（json は常に出力）
--max-file-size SIZE    1ファイルの読み取り上限
--workers N             並行度（既定 1）
--cpu-limit / --io-limit  CPU 使用率・読み取り速度の上限（6章）
--rules-mode MODE       replace（既定）| overlay
--strict                スキップ・エラーがあれば終了コード 1
--process-info          稼働プロセスの情報（実行ファイルのパスとロード済みライブラリ）を使う（既定: 使わない。Linux のみ）
--max-duration DUR      実行時間上限（超過時は途中結果を「未完了」と明記して終了）
--label K=V             台帳連携用の任意タグ（システム名、管理部署など）
--dry-run               何をスキャンするかの計画だけをログに出して終了
```

- アプリケーションとして環境変数・カレントディレクトリ・ホームディレクトリから設定やルールを**暗黙に読み込まない**。
  Go ランタイム自体が読む環境変数（`GODEBUG`、`GOTRACEBACK` 等）は、設定されていたら警告を記録し、危険なもの（コア出力）は起動時に無効化する（4.2）。
- 終了コード: `0` 完了（スキップがあっても正常。ネットワーク FS のスキップ等は通常の動作のため） / `1` `--strict` 指定時にスキップ・エラーあり / `2` 引数エラー / `3` 致命的エラー・未完了。ジョブ管理ツールからの実行を想定。
- 出力ファイル名: `kagiya-<ホスト名>-<UTC日時>-<scan_id 短縮>.json`（定期実行で衝突しない）。既存ファイルは上書きしない。
- `--exclude` は `**` を含むグロブ。Windows では大文字小文字を区別しない。標準エラー出力の進捗は件数のみ（パスを出さない）。
- 時刻は UTC で扱う（タイムゾーンデータベースの読み込みを避ける）。

### 3.3 パッケージ構成

```
cmd/kagiya/            エントリポイント
internal/cli/          引数解析、サブコマンド
internal/safefs/       ★ファイルを開く唯一の経路。ネットワークFS判定、除外、サイズ上限、権限エラー記録
internal/platform/     OS依存（優先度低下、マウント表、レジストリ読取、出力ファイルの権限、サンドボックス）
internal/rules/        ルールの読み込み・検証・書き出し（内包は go:embed）
internal/catalog/      暗号カタログ（別名→正規ID、評価情報）
internal/parse/        形式パーサ群（der, pem, keystore, elf, pe, classfile, 各設定文法）
internal/collect/      コレクタ群（ospolicy, apps, certstore, fscrawl, source, binary）
internal/resolve/      実効値解決（解決チェーン、OpenSSL 暗号文字列の展開など）
internal/model/        データモデル（結果 JSON の型）
internal/output/       json / cbom / csv
internal/report/       HTML 生成（テンプレートと CSS/JS を内包）
internal/logx/         ログ
rules/                 内包ルール定義（YAML）
testdata/              ディストリ別・版別の実設定ファイル等のフィクスチャ
```

設計上の柱: **ファイルを開く処理は `safefs` だけ**、**書き込みは `output` と `logx` だけ**に集約する。
個別関数の禁止では漏れる（`os.ReadFile`、`filepath.Walk`、`elf.Open`、`zip.OpenReader` 等も内部でファイルを開く）ため、
**`os` と `path/filepath` の import 自体を `safefs` / `platform` / `output` / `logx` / `cli` 以外で禁止**し、パーサは `io.ReaderAt` 等のインターフェースだけを受け取る。CI の静的検査で強制する。

---

## 4. 安全設計（禁止事項への対応）

### 4.1 禁止事項と対応の一覧

| 禁止事項 | 対応 |
|---|---|
| 出力先以外に書き込まない | 書き込みは出力ディレクトリとログディレクトリのみ（ログ先は要件で認められた例外）。一時ファイルを作らない（メモリ上で処理、または出力先に `.partial` で書いてリネーム）。スキャン対象は読み取り専用で開く |
| ポート待ち受け・外部通信なし | 4.2 の三層防御 |
| ネットワーク FS を読まない | 4.3 |
| 暗黙の通信 | 4.4 |
| 秘密値を出さない | 4.5 |
| 自動更新・テレメトリなし | 実装しない。通信コードがないため構造的に不可能 |
| 出力は作成者のみ可読 | 4.6 |
| CPU 優先度を下げる | 6章 |

### 4.2 通信しないことの保証（三層）と、その保証範囲

**保証範囲の定義**: 「本プロセスがソケット等の通信 API を使わない」「ネットワーク越しのファイルシステム（NFS/SMB 等）と、開くと取得が発生するファイルに触れない」まで。
次のものは本ツールでは検出・制御できず、保証範囲外として利用者向け文書に明記する:
ブロックレベルのネットワークストレージ（iSCSI/SAN/NBD 等）上のローカル FS、アンチウイルス・EDR のクラウド照会、OS の監査ログ転送など第三者による間接的な通信。

1. **通信コードを持たない（ビルド時保証）**
   - 依存グラフ（vendor 含む）に `net`、`net/http`、`os/exec`、`plugin`、`crypto/tls`、`crypto/x509`、`os/user` が含まれないことを CI で検査する。
     レビューでの実測により、本設計が使う標準パッケージ・`x/sys/unix`・`x/text`・YAML パーサはこれらを引き込まないことを確認済み。
   - `syscall` / `unsafe` / `//go:linkname` / アセンブリは任意のシステムコールを呼べるため、使用を `internal/platform` のみに許可する静的検査を置く（vendor も対象）。`internal/platform` は小さく保ち、重点レビュー対象とする。
   - Linux: 生成バイナリにソケット・exec 系シンボルが無いことを検査（実測で確認済み）。
   - Windows: 標準 `syscall` パッケージ由来の**未使用の** Winsock/DNS API 定義（遅延ロード用の名前）がバイナリ内に残ることを実測で確認した。したがって Windows での主張は
     「`net` を含まず、通信 API を呼ぶコード経路がない。`ws2_32.dll` 等はロードされない」とし、実行時にロード済みモジュールを列挙して `ws2_32` / `dnsapi` / `winhttp` / `wininet` が無いことを検査する結合テストで裏付ける。
2. **触れない（実行時の回避）**: 4.3。
3. **できない（実行時の封じ込め、ベストエフォート）**
   - Linux: seccomp フィルタ（`SECCOMP_FILTER_FLAG_TSYNC` で全スレッドに適用、`seccomp_data.arch` を検査して 32bit ABI 経由の迂回を防止、
     `socket`/`connect`/`bind`/`listen`/`accept*`/`sendto` 等に加え `execve`/`execveat`/`io_uring_*`/`ptrace`/`process_vm_*` を拒否、違反時は `EPERM`）。`PR_SET_NO_NEW_PRIVS` は全スレッドに適用。
   - Windows: Job オブジェクトで子プロセス生成を禁止。不要な特権をトークンから削除。
   - Landlock（書き込み先限定）は必須対象 OS の多く（RHEL 8、Ubuntu 20.04 以前）に存在しないため v1 では扱わない。
   - 適用結果は `meta.hardening` とログに記録。適用できなくてもスキャンは続行（層1・2が主たる保証）。
   - 管理者が OS 側で本バイナリの通信を遮断する手順（ファイアウォール規則等）も文書で案内する。

コアダンプ・クラッシュレポート対策: 起動直後にコアダンプを無効化し（`RLIMIT_CORE=0`、`PR_SET_DUMPABLE=0`）、Go のトレースバック設定を固定する
（`GOTRACEBACK=crash` によるコア出力や Windows エラー報告への引き渡し＝出力先以外への書き込み・秘密流出・通信を防ぐ）。

検証手段: ネットワーク名前空間を切り離した環境と `strace -f -e trace=network` 下の結合テストを CI に組み込み、利用者が再現できる手順として文書化する。

### 4.3 ネットワークファイルシステム等の回避

**原則1: 触れる前に判定する。** 自動マウント（autofs）は stat だけでマウント＝通信が起き、NFS は `statfs` でも通信するため、判定はマウント表とすでに開いたハンドルの情報だけで行う。
**原則2: パス文字列ではなくディレクトリハンドル相対で辿る。** パス文字列で開くと途中要素のシンボリックリンクが辿られ、判定後の差し替え（競合）も起きるため。

Linux:
- `/proc/self/mountinfo` からマウント表を構築（`\040` 等のエスケープ、重ねマウントを正しく扱う）。種別が拒否リスト
  （`nfs*`, `cifs`, `smb*`, `ceph`, `glusterfs`, `lustre`, `gpfs`, `beegfs`, `9p`, `afs`, `ncpfs`, `davfs`, `fuse.sshfs`, `autofs` ほか）のマウントポイント配下は**システムコールを発行せずに**スキップ。
  許可リストにない `fuse.*` や未知の種別は既定スキップ（安全側）。リストはルールで拡張可能。
- overlayfs は `lowerdir`/`upperdir` の所在、loop デバイスは backing file の所在も判定に含める。
- 走査は `openat` + `O_NOFOLLOW|O_DIRECTORY|O_NONBLOCK` で1要素ずつ。`fstatat` には `AT_SYMLINK_NOFOLLOW|AT_NO_AUTOMOUNT`。カーネルが対応していれば `openat2`（`RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS`）を使う。
- 開いた後の再確認は `fstat` の `st_dev` とマウント表の major:minor の照合で行う（`fstatfs` は使わない）。btrfs サブボリューム等、マウント境界でなくても `st_dev` が変わる場合を考慮する。
- 探索ではシンボリックリンクを辿らない。設定ファイルが参照するパス（証明書ファイル等）は、**1要素ずつマウント表と照合しながら自前で解決**する（`realpath` 相当の一括解決は使わない）。
- `proc`, `sysfs`, `devtmpfs` 等の擬似 FS は探索しない（OS 設定取得のための特定ファイルの直接読取のみ）。
- 稼働プロセスの情報（5.3）は、マウント名前空間が自プロセスと同じプロセスに限る。異なるもの（コンテナ内プロセス等）は対象外として記録。

Windows:
- `DRIVE_REMOTE` のドライブ、UNC パス、`subst`／ネットワーク割り当てドライブは対象外。
- 1要素ずつ `FILE_FLAG_OPEN_REPARSE_POINT` 付きで開き、リパースポイント（ジャンクション、シンボリックリンク、マウントポイント）は辿らない。
- クラウド同期のプレースホルダ（`RECALL_ON_DATA_ACCESS` / `RECALL_ON_OPEN` / `OFFLINE` 属性）は、ファイルは開かず、ディレクトリは列挙しない。属性は親ディレクトリの列挙結果から得る。開く際は `FILE_FLAG_OPEN_NO_RECALL` を付ける。
  （プレースホルダ属性が本ツールのプロセスからどう見えるかは Phase 0 で実機検証する。）

共通:
- スキップは結果 JSON の `skipped[]`（理由コード `network-fs` / `automount` / `cloud-placeholder` / `unknown-fs` / `foreign-mount-namespace` 等）とログの両方に記録。
- 通常ファイル以外（FIFO、ソケット、デバイス）は開かない。開いた後はハンドルに対する `fstat` で再確認。
- **出力先・ログ先がネットワーク FS の場合は起動時にエラーで拒否**（書き込みが通信になるため）。出力先・ログ先自身はスキャン対象から自動除外。
- **本ツールの実行ファイル自体がネットワーク FS 上にある場合**（共有フォルダからの直接実行）は、実行中の読み込みがカーネルによる通信になる。既定では起動を拒否し、ローカルにコピーして実行するよう案内する。

### 4.4 暗黙の通信が起き得る処理と対応

| 処理 | 対応 |
|---|---|
| 証明書チェーン検証（AIA/CRL/OCSP 取得） | OS や標準ライブラリの検証 API を呼ばない。チェーンはローカルで見つかった証明書同士を Subject/Issuer と SKI/AKI の突き合わせで「関連付ける」だけ（信頼性判断はしない） |
| XML の外部実体・DTD・XInclude | `encoding/xml` は解決しない。XInclude 等も実装しない |
| 名前解決 | 設定中のホスト名は文字列として扱うのみ。UID→ユーザー名、SID→アカウント名の変換をしない |
| Windows 証明書ストア API | CryptoAPI のチェーン構築を使わず、レジストリ上のストア実体を直接パース |
| リモートレジストリ | ローカルハイブのみ。リモート接続 API を使わない |
| 設定ファイルの include | ローカルパスのみ `safefs` 経由で辿る。URL 形式・UNC は辿らず記録 |

### 4.5 秘密情報を出力しない仕組み

- **許可リスト方式の抽出**: 設定ファイルから取り出すのはルールで定義されたディレクティブだけ。未知のディレクティブの値は読み捨てる。
- **値の型と検証**: ルールは各ディレクティブに値の型（`cipher-list`, `protocol-list`, `curve-list`, `path`, `int`, `bool`, `enum`, `version`, `secret` …）を宣言する。出力前に型ごとのバリデータ（文字種・長さ・カタログ照合）を通し、通らない値は出力しない。自由文字列をそのまま出す型は設けない。
  版文字列など**正規表現で捕捉した値にも同じ検証**をかける。
- **カタログにないアルゴリズム名**: 棚卸し漏れを可視化するため記録するが、文字種・長さの制限（英数字と一部記号、64 文字以内）を満たす場合のみ名前を出す。満たさない場合は「不明な値あり」と長さだけを記録する。
- **`secret` 型**: パスワード等は「設定されている／平文で記載されている」という事実のみ記録し、値は保持もしない。
- **秘密鍵**: 形式・アルゴリズム・鍵長・暗号化有無と、鍵ファイルに含まれる**公開成分**から計算した公開鍵フィンガープリント（証明書との対応付け用）のみ。
  秘密成分やファイル内容全体のハッシュは計算しない（照合オラクルになるため）。公開成分が得られない鍵（暗号化された鍵等）の ID は、内容ではなく場所（デバイス・inode・パス）から作る。
- **ソースコードの証跡**: 生の行は出力しない。一致した API 名と、抽出したアルゴリズム指定文字列、ファイル・行・列のみ。
- **プロセス情報**: 既定では一切読まない。`--process-info` が明示された場合に限り、Linux で `/proc/<pid>/exe`（実行ファイルのパス）と `/proc/<pid>/maps`（ロード済みライブラリのパス）だけを読む。
  `/proc/<pid>/environ`・`cmdline`・`mem` など秘密を含み得るものは、オプションの有無にかかわらず**読まない**（`cmdline` も引数にパスワードが含まれることがあるため対象外とする）。Windows ではプロセスを調べない。
- **パーサのエラー**: エラーメッセージに入力の断片が含まれ得るため、ログには種別と位置のみを記録する。
- **ログ**: 同じ規則に従う。ファイル由来の文字列は制御文字をエスケープ（ログ偽装対策）。
- **外部ルールの信頼境界**: 上記の検証があっても、ルールは「どのファイルのどの値を読むか」を決めるため、外部ルールを書ける人は本ツールの実行権限で読める情報の一部を出力に導ける。
  外部ルールは**バイナリと同等に信頼できるものだけを使う**前提とし、ルールディレクトリ・全ファイル・親ディレクトリが他ユーザー書き込み可、またはシンボリックリンクを含む場合は読み込みを拒否する。
  ルールが参照できるパスの種別もスキーマで制限する。
- ファイルパス、証明書の Subject/SAN 等は秘密ではないが機微情報であり、出力全体を機密として扱う（4.6）。仮名化オプションは将来検討。
- **キーストアのパスワード**: パスワードを使ってキーストアを開く機能は実装しない。設定ファイルに書かれたパスワードも、既定値（`changeit` 等）も使わない。

### 4.6 出力ファイルの保護

- Linux: ディレクトリ `0700`、ファイル `0600`。`O_EXCL|O_NOFOLLOW` で新規作成し、`.partial` からの確定は既存ファイルを上書きしない方法（`renameat2(RENAME_NOREPLACE)` または `link`）で行う。
- Windows: **作成時に**セキュリティ記述子を渡し、継承を切った DACL（実行ユーザーの SID のみ許可）と所有者を確定する（作成後に設定すると、その間は既定の権限で読めてしまうため）。
- 出力先ディレクトリが他ユーザー書き込み可の場合は拒否する。
- HTML レポート・CBOM・CSV・ログも同じ扱い。

### 4.7 ツール自身がバックドアにならないために

- 通信・子プロセス起動・動的コード読み込み（プラグイン、スクリプト実行）の機能を持たない。ルールは**純粋なデータ**（表と正規表現）で、任意コードを表現できない。
- 特権を要求・昇格しない。setuid での実行は拒否。Windows のバックアップ特権等で ACL を迂回しない。権限がなければ記録して先へ進む。
- 外部ルールの扱いは 4.5 のとおり。使用したルールセットの SHA-256 と日付を結果に記録。
- すべてのパーサは入力を敵対的とみなす: サイズ・ネスト深さ・展開率（ZIP 爆弾）の上限、ファイル単位の panic 回復、Go 標準のファジングテスト。
- HTML レポートは外部リソース参照ゼロ（CDN・Web フォントなし）、CSP メタタグで外部通信を禁止、埋め込みデータは文脈に応じてエスケープ（ファイルパスや証明書の Subject は攻撃者が制御し得るため）。
- CSV は数式インジェクション対策（`=`,`+`,`-`,`@` 始まりのセルを無害化）。
- 配布物: 再現可能ビルド（`-trimpath`、依存固定）、ツール自身の SBOM、署名付きリリース、チェックサム。

---

## 5. スキャン対象と方式

### 5.1 コレクタ一覧

| コレクタ | 対象 | 既定 |
|---|---|---|
| `ospolicy` | OS 全体の暗号設定 | 有効 |
| `apps` | サーバーアプリケーションの設定と実効値 | 有効 |
| `certstore` | OS 標準・アプリ固有の証明書ストア | 有効 |
| `fscrawl` | 探索起点配下の証明書・鍵・キーストアファイル | 有効 |
| `binary` | 実行ファイル・ライブラリ・class/JAR | 有効（検出済みアプリのバイナリ＋探索起点配下） |
| `source` | ソースコードと開発系設定ファイル | `--source-dir` 指定時のみ |

### 5.2 OS の暗号設定（`ospolicy`）

Linux:
- システム全体の暗号ポリシー: `/etc/crypto-policies/config`、`state/current`、`back-ends/*.config`（RHEL 8+ 系）
- FIPS モード: `/proc/sys/crypto/fips_enabled`
- OpenSSL 設定: `openssl.cnf`（ディストリごとの場所、`.include` をローカルに限り追跡）
- GnuTLS / NSS / libssh のシステム設定、`krb5.conf`（許可暗号種別）
- SSH: `sshd_config` / `ssh_config`（`Include`、`*.d` ディレクトリ含む）
- Java: 検出した各 JDK/JRE の `java.security`（無効化アルゴリズム等）
- パスワードハッシュ方式: `login.defs`、PAM 設定（`/etc/shadow` は読まない。9章 C）

Windows（主にレジストリのローカルハイブから読取。64bit と WOW6432Node の両方を見る。OpenSSH for Windows や IIS はファイル）:
- Schannel: プロトコル、暗号、ハッシュ、鍵交換の有効/無効、暗号スイート順序（ポリシー／ローカル）、楕円曲線順序
- FIPS ポリシー、.NET Framework の強力な暗号設定（`SchUseStrongCrypto`、`SystemDefaultTlsVersions`）
- Kerberos 暗号種別、NTLM 互換レベル、RDP セキュリティ層、WinRM、OpenSSH for Windows の設定
- HTTP.sys の SSL バインド情報（レジストリ上の形式は非公開のため Phase 2 冒頭で調査。読めない場合は IIS の設定ファイルからの取得に留める）

どちらの OS も、「未設定のときの既定値」を OS バージョン／ビルド別の表としてルールに持ち、未設定項目を補完する（層: `os-default`）。

### 5.3 サーバーアプリケーション（`apps`）

アプリは無数にあるため、**アプリごとのコードを書かず「アプリプロファイル」（ルール定義）で追加できる**構造にする。

処理の流れ:
1. **発見**: 既定の設定パスと、サービス定義（systemd ユニットの `ExecStart`・`Environment=`・`EnvironmentFile=`、Windows サービスの `ImagePath`）から、インスタンス（実行ファイル＋設定ファイル）を特定。
   サービス定義に書かれた設定ファイル指定の引数や暗号関連の環境変数（`OPENSSL_CONF` 等、許可リストの名前のみ）はここから得る（稼働プロセスの `environ`・`cmdline` は読まない）。
   `--process-info` 指定時のみ、Linux で稼働プロセスの `/proc/<pid>/exe` も使う（自プロセスと同じマウント名前空間のものに限る）。
2. **バージョン特定**（外部コマンドを実行しない）:
   - パッケージ管理情報: dpkg の status ファイル、**rpm DB**（RHEL 8 は Berkeley DB、RHEL 9 は SQLite。読み取り専用の最小リーダを実装。稼働中 DB をロックなしで読むため、ヘッダ検証と再試行を行う）。
     RHEL は修正をバックポートするため上流の版番号だけでは既定値を特定できない。**「ディストリ＋パッケージのリリース」を既定値表のキーに含める**。
   - 実行ファイル内の版文字列（例: `nginx/1.20.1`）、PE のバージョンリソース（パッケージ管理外のインストール向け）
   - 特定できない場合は `unknown` とし、既定値解決の信頼度を下げる
3. **リンクしている暗号ライブラリの特定**:
   - 既定: ELF の `DT_NEEDED` を RPATH/RUNPATH・`ld.so.cache`・標準探索パスで解決。PE はインポート表と同ディレクトリの DLL。実行時に `dlopen` されるモジュールは分からないため、その旨を信頼度に反映する。
   - `--process-info` 指定時: `/proc/<pid>/maps` から実際にロードされているライブラリを得る（`dlopen` されたモジュールも分かる。削除済みファイルの表示は「更新後に再起動されておらず旧ライブラリで稼働中」を意味する）。
   - ライブラリ内の版文字列とパッケージ情報から版を特定。
4. **設定のパース**: 文法パーサは有限個をコードで実装（nginx 系ブロック、Apache 系、INI、key=value、sshd 系、XML、YAML、JSON、Java properties、postfix 系）。プロファイルが使う文法と include 規則を指定。
5. **抽出**: プロファイルが定義するディレクティブを取得。スコープと継承の規則はアプリごとに異なるため、単純なものはデータで、複雑なものは解決フック（5.4）で扱う。
6. **実効値解決**（5.4）。

外部コマンドを実行しない理由: root で任意のバイナリを起動することになり（PATH 汚染・改ざんバイナリのリスク）、負荷と副作用が読めず、「読み取りで完結」の原則に反するため。代償として版特定の精度が落ちる場面があるが、その場合は不確かさを明示する。

初期対応アプリ（フェーズ計画参照）: OpenSSH, nginx, Apache httpd, OpenSSL 設定, Postfix, Dovecot, Tomcat, HAProxy, MySQL/MariaDB, PostgreSQL, IIS, OpenVPN, strongSwan/Libreswan, vsftpd, OpenLDAP ほか。

### 5.4 実効値の解決

要件は「アプリの設定 ＞ OS の暗号ポリシー ＞ ライブラリのデフォルト」の順での解決を求めている。これを基本形としつつ、
現実には次のような例があるため、**単純な「最初に見つかった層を採用」ではなく、層ごとの演算を合成するモデル**とする。

- 層は値を「上書き」するとは限らず、「制限」（上限・下限・積集合）として働くことがある。例: アプリが暗号スイート文字列を明示しても、OS ポリシー由来のセキュリティレベルが別経路でそれを絞る。
- アプリは未記載の項目にも自身の既定値をライブラリへ明示的に設定することがある（nginx の `ssl_protocols` 等）。この場合「未記載＝OS ポリシーに従う」にはならない。
- 順序が逆転する例がある。RHEL 8 の sshd は OS ポリシーがコマンドライン引数として渡され、`sshd_config` の記載より優先される（RHEL 9 では仕組みが変わる）。

モデル:
- 層: `app-config`（明記）/ `app-default`（アプリの既定値。版・ディストリ別）/ `os-policy` / `library-default` / `os-default`。
- 各層は、パラメータごとに演算の種類を持つ: `override`（置換）/ `restrict`（制限）/ `modify`（追加・削除。sshd の `+`/`-`/`^` 等）。
- 層の適用順と演算は**アプリプロファイル側で宣言**する（ディストリ・版の条件付き）。既定は要件の順。
- アプリ固有の込み入った規則（設定の継承・マージ、sshd の先勝ちと `Match`、Apache の vhost マージ等）は、プロファイルから名前で参照する**解決フック**（Go コード。有限個）で実装する。
  「アプリごとのコードを一切書かない」ことは目指さず、「単純なアプリはデータだけで追加でき、複雑なアプリは小さなフックを足す」構造とする。
- 出力には、合成結果（実効値）に加えて**各層の生の値を事実として必ず残す**。合成規則に誤りがあっても、後から検証・再解決できる。
- OpenSSL の暗号文字列（`HIGH:!aNULL:!MD5`、`PROFILE=SYSTEM`、`@SECLEVEL=2` 等）は版別・ディストリ別の暗号スイート表に対して評価し、具体的なスイート一覧に展開する。TLS 1.3 のスイートは別管理として扱う。
- 各値に `state`（`configured` / `effective` / `default`）と `confidence` を付ける。版が不明、表にない版、ビルド時オプションやディストリ独自パッチに依存する等で解決しきれない場合は `unresolved` と理由を記録し、推測で埋めない。

正しさの検証（開発時のみ。ツール本体は外部コマンドを実行しない）:
CI 上の各ディストリのコンテナ内で `sshd -T`、`openssl ciphers -V`、実際のハンドシェイクによる列挙を行って正解データを採取し、kagiya の解決結果と突き合わせる。
版別スイート表もこの仕組みで実物から生成する。この突き合わせが通ることを Phase 1c の完了条件とする。

### 5.5 証明書・鍵・キーストア（`certstore`, `fscrawl`）

OS 標準ストア:
- Linux: `/etc/ssl/certs`、`/etc/pki/tls`、`/etc/pki/ca-trust`、`/usr/local/share/ca-certificates` 等（ディストリ別にルール定義）
- Windows: システム証明書ストアの実体を直接パースする。ローカルマシン・グループポリシー・Enterprise の各ストア（レジストリ）、実行ユーザーのストア（レジストリおよび `%APPDATA%\Microsoft\SystemCertificates` 配下のファイル）、
  ロード済みのサービスアカウントのハイブ、サービス別ストア。物理位置の一覧はルール（`os/windows.yaml`）で定義する。秘密鍵の有無はプロパティ（プロバイダ名・コンテナ名）から判定

アプリ固有ストア:
- Java: `cacerts`、JKS / JCEKS / PKCS#12 / BKS
- NSS DB（`cert9.db` 等）: 存在と場所を記録（内容のパースは Phase 6 で検討）
- アプリ同梱 CA バンドル（`cacert.pem`、`certifi` 等）、アプリ設定が参照する証明書・鍵ファイル

ファイル探索:
- 拡張子とマジック（PEM ヘッダ、DER 構造、キーストアのマジック）で判定。対象: X.509 証明書、CSR、CRL、各形式の秘密鍵・公開鍵（PKCS#1/8、SEC1、OpenSSH、PuTTY PPK、PGP 鍵）、キーストア。
- SSH の `authorized_keys`・`known_hosts`・ホスト鍵、Kerberos keytab の暗号種別も対象。PGP 鍵・PuTTY PPK は Phase 6。
- 既定の探索起点 — Linux: `/etc`, `/opt`, `/usr/local`, `/srv`, `/var/www`, `/root`（`/home` は巨大・自動マウント・個人ファイルの懸念から既定では含めない）。Windows: `%ProgramData%`, `%ProgramFiles%`, `%ProgramFiles(x86)%`, `C:\inetpub`。`--roots /` 等でローカル FS 全体も指定可能（9章の相談事項）。

パスワード保護されたコンテナ（PKCS#12 等）は、既定ではパスワードなしで読める範囲（外側構造、MAC・PBE アルゴリズム、反復回数）を記録。JKS は証明書エントリをパスワードなしで読める。
近年の Java の既定は PKCS#12 で証明書も暗号化されるため、中身が見えないストアが多くなる。パスワードは一切使わない方針（9章 A）のため、
その場合は「暗号化されており内容未確認」のキーストア資産として記録し、レポートで**未確認の範囲**として明示する。設定ファイルが別途参照する証明書ファイル（PEM 等）は通常どおり読む。

### 5.6 ソースコード解析（`source`）

対象言語（初期）: Java、VB.NET、C#、PowerShell、シェルスクリプト（sh/bash 系。Windows バッチは Phase 6）。
VB.NET と C# は同じ .NET の API を使うため、**API ルールは `source/dotnet/` に1本化して共有**し、言語ごとに持つのは字句解析器だけとする（PowerShell からの .NET 型利用も同じルールを参照する）。言語は「字句解析器（コード）＋ルール（データ）」の組で追加できる。

正規化（スタイル差の吸収）— 言語ごとの軽量な字句解析器でトークン列に変換してから照合する:
- コメント除去、空白・改行・行継続（VB の `_`、シェルの `\`、PowerShell のバッククォート）の正規化
- 大文字小文字を区別しない言語（VB.NET、PowerShell）の識別子の畳み込み
- 文字列リテラルの連結の畳み込み（`"AES" + "/CBC/" + "PKCS5Padding"`）、Java の Unicode エスケープの復元
- 完全修飾名と import/Imports による短縮名の同一視、PowerShell の別名・パラメータ省略形の正規化
- 同一ファイル内の定数（`static final String ALG = "AES"` 等）の単純な置換。これ以上のデータフロー解析はしない
- 文字コード: BOM、UTF-8 妥当性、UTF-16、Shift_JIS、EUC-JP を判定し、**字句解析の前に**デコード（Shift_JIS の 2 バイト目が `\` と重なる問題を避ける）
- 多数のルールを全ファイルに適用するコストを抑えるため、リテラル文字列による前段フィルタで候補ルールを絞る

照合ルールはトークン列上のパターン（呼び出し・型参照・コマンド＋オプション）で、引数からアルゴリズム指定文字列を捕捉し、
カタログの解釈器（例: JCA の `"AES/CBC/PKCS5Padding"`、`"AES"` 単独指定時のプロバイダ既定モード）で正規化する。

対応 API（初期）:
- Java: JCA/JCE（`Cipher`, `MessageDigest`, `Signature`, `KeyPairGenerator`, `KeyGenerator`, `Mac`, `SecretKeyFactory`, `KeyAgreement`, `SSLContext` 等）、Bouncy Castle（軽量 API・PQC 含む）、Google Tink、Apache Commons Codec、Spring Security Crypto、Jasypt、JWT ライブラリ（jjwt、Nimbus JOSE）、Guava Hashing
- .NET（VB.NET・C# 共通）: `System.Security.Cryptography`（各 `*.Create`、`*CryptoServiceProvider`、`*Managed`、`CryptoConfig`）、Bouncy Castle C#、DPAPI、CNG/CAPI の P/Invoke 宣言、`ServicePointManager.SecurityProtocol`
- PowerShell: .NET 型の利用、`New-SelfSignedCertificate`、`Get-FileHash`、`ConvertTo-SecureString`、`Protect-CmsMessage`、TLS 設定系
- シェル: `openssl` 各サブコマンド、`ssh-keygen`、`gpg`、`keytool`、`curl`/`wget` の TLS オプション、`md5sum`/`sha*sum`、`certutil` 等

設定ファイル: `application.properties`/`.yml`（Spring の `server.ssl.*` 等）、`java.security`、`web.config`/`app.config`（`machineKey`、WCF のアルゴリズムスイート）、`appsettings.json`、ビルド定義（`pom.xml`、`build.gradle`、`*.vbproj`、`packages.config`）中の暗号ライブラリ依存。

### 5.7 バイナリ解析（`binary`）

逆アセンブル・逆コンパイルは行わず、ファイル形式上のメタデータと文字列のみを読む。

| 形式 | 読むもの |
|---|---|
| ELF | 動的セクション（`DT_NEEDED`、soname）、動的シンボル（未定義シンボル＝利用 API、例: `EVP_aes_256_gcm`）、静的リンクされたライブラリの版文字列、Go バイナリのビルド情報（依存モジュール） |
| PE | インポート表・遅延インポート表（`bcrypt.dll`, `ncrypt.dll`, `crypt32.dll`, `advapi32.dll` の暗号 API、OpenSSL 系 DLL）、バージョンリソース、版文字列 |
| .NET アセンブリ | マネージド PE のインポート表には暗号 API が現れないため、CLI メタデータ（型参照・メンバー参照の名前、ユーザー文字列）を読む。Java の定数プールと同じ位置づけで、逆コンパイルではない |
| Java class / JAR / WAR / EAR | 定数プール中のアルゴリズム名文字列と暗号 API へのメソッド参照。入れ子アーカイブは深さ・サイズ・展開率に上限 |

バイナリ由来の検出は「使用の可能性」（`state: capability`）として、設定やソース由来の検出と区別する。

### 5.8 共通事項

- 読み取り権限がない場合: 理由コード `permission-denied` でログと `skipped[]` に記録して継続。
- 除外: `--exclude`（グロブ）、`--exclude-from`。除外でスキップしたことも記録。
- 上限超過（サイズ、時間、ネスト）によるスキップも記録。結果 JSON に網羅性サマリ（走査数・スキップ数・理由別内訳）を持たせ、**「見ていないもの」が分かる**ようにする。

---

## 6. 負荷を抑える設計

優先度を下げるだけでは不十分（空きコアがあれば 1 コアを使い切り、監視の閾値に触れ得る）なので、**優先度の低下**と**自前の流量制限**を併用する。

優先度:
- Linux: nice 19 と I/O 優先度 idle を設定。これらはスレッド単位の属性で、Go は複数の OS スレッドを持つため、全スレッドに適用する仕組み（`syscall.AllThreadsSyscall`）を使い、
  適用後に全スレッドの nice 値を `/proc/self/task/*/stat` で確認して `meta.hardening` に記録する。I/O 優先度は I/O スケジューラによっては効かないため補助と位置づける。
- Windows: `IDLE_PRIORITY_CLASS` ＋ I/O 優先度 Low。バックグラウンドモード（`PROCESS_MODE_BACKGROUND_BEGIN`）はワーキングセットが極端に制限され逆に遅くなる報告があるため使わない。
  Job オブジェクトで CPU レート上限とメモリのハード上限を設定する。
- 失敗時は警告を記録して継続。

流量制限（既定で有効。数値は Phase 0 の負荷試験で確定し、すべてオプションで変更可）:

| 項目 | 既定値（暫定） |
|---|---|
| 並行度 `--workers` | 1 |
| CPU 使用率の上限 `--cpu-limit`（処理と休止の比率で制御） | 1 コアの 25% |
| 読み取り速度の上限 `--io-limit` | 20 MiB/秒 |
| メモリ上限（Go のソフトリミット。Windows は Job のハード上限も） | 512 MiB |
| 1ファイルの読み取り上限 `--max-file-size` | 64 MiB（超過分は先頭と必要部分のみ、またはスキップ） |
| 実行時間上限 `--max-duration` | なし（指定推奨） |

その他:
- 読む量を最小にする: 種別判定は先頭数 KB、ELF/PE は必要なヘッダ・表のみ。
- 探索は既定で限定された起点のみ。同一 inode の重複排除。
- ファイルをロックしない: Windows では読み取り・書き込み・削除をすべて共有許可で開く（標準 API は削除共有を付けないため自前で開く）。アプリのログローテーションや設定差し替えを妨げない。
- Linux では可能な場合 `O_NOATIME`（所有者または特権が必要。不可なら通常オープンに戻し件数を記録）。
- `fadvise(DONTNEED)` は本番アプリのキャッシュを追い出し得るので使わない。大量読取によるキャッシュへの影響は流量制限と読取量の最小化で抑える。
- 割り込み（SIGINT/SIGTERM、Ctrl+C）で安全に停止し、途中結果を「未完了」と明記して出力。
- 本ツールの制御外の影響（アンチウイルスのリアルタイムスキャン負荷、ファイルアクセス監査ログの増加、EDR による検知）は利用者向け文書に明記し、
  事前申請に使える「読み取り対象一覧」（`--dry-run` の出力）を提供する。

---

## 7. データモデル

### 7.1 入力

| 入力 | 内容 |
|---|---|
| コマンドライン引数 | 3.2 |
| ルール定義 | 内包（既定）または `--rules DIR`（7.3） |
| ローカルシステム | ファイル、レジストリ（Windows）、`/proc`・`/sys` の特定項目（Linux） |
| 結果 JSON | `convert` / `report` の入力 |

### 7.2 出力（独自 JSON スキーマ `kagiya-inventory`。Phase 3 完了まで `v0`）

考え方:
- **事実と評価の分離**: スキャン結果は「何がどこにあるか」という事実を主とする。危殆化・量子耐性の評価はカタログに基づく付加情報で、
  `report` / `convert` 実行時に**その時点のルールで再評価**できる。新たな危殆化が判明しても再スキャンなしで過去の結果を評価し直せる。
- **資産と出現の分離**: 同じ証明書・同じアルゴリズムが多数の場所に現れるため、一意な「資産」と、場所・文脈を持つ「出現」に分ける（CycloneDX CBOM の component / occurrence と対応が取りやすい）。
- **安定 ID**: スキャン間の差分（追加・消滅・変化）を取れるようにする。出現の ID は「資産・ルール・正規化した場所（行番号を含めない）・スコープ・用途」のハッシュ＋同一キー内の序数。
- **生の名前の保存**: すべての出現に、見つけたままの名前と命名体系（`jca` / `openssl` / `oid` / `ssh` / `iana` …）を保存する。カタログの ID が将来改名・分割されても、過去の結果を再正規化・再評価できる。
- **順序を持つ設定の表現**: 暗号スイート一覧のように順序に意味がある設定は `settings[]`（サービス × スコープ × 項目）として、順序付きの資産参照と解決チェーンを持たせる。個々の出現に分解して順序を失わない。
- **ホストの同一性**: ホスト名だけでは「同一ホストの別時点」と「別ホスト」を区別できないため、machine-id / MachineGuid の鍵付きハッシュを `host.id` とする（生の値は出さない）。
- **パスの表現**: UTF-8 として不正なファイル名（EUC-JP・Shift_JIS のファイル名等）は、損失のないエスケープ表記で記録する。

```jsonc
{
  "schema": "kagiya-inventory/v0",
  "meta": {
    "scan_id": "…", "started_at": "…", "finished_at": "…", "completed": true,
    "tool": { "version": "…", "build": "…" },
    "rules": { "source": "builtin|external", "version": "…", "sha256": "…" },
    "host": { "id": "…", "hostname": "…", "os": "linux", "distro": "rhel", "os_version": "9.4",
              "kernel": "…", "arch": "amd64" },
    "labels": { "system": "勘定系", "owner": "…" },
    "invocation": { "roots": ["…"], "source_dirs": ["…"], "excludes": ["…"], "collectors": ["…"] },
    "privilege": { "elevated": true },
    "hardening": { "priority_lowered": true, "seccomp": "applied", "landlock": "unsupported" }
  },

  "assets": [
    { "id": "alg:aes-256-gcm", "type": "algorithm",
      "algorithm": { "family": "AES", "primitive": "aead", "mode": "GCM", "key_bits": 256 } },
    { "id": "cert:sha256:ab12…", "type": "certificate",
      "certificate": { "subject": "…", "issuer": "…", "serial": "…",
        "not_before": "…", "not_after": "…", "is_ca": false, "self_signed": false,
        "signature_algorithm": "alg:sha256-with-rsa",
        "public_key": { "algorithm": "alg:rsa-2048", "fingerprint_sha256": "…" },
        "key_usage": ["…"], "san": ["…"], "issuer_ref": "cert:sha256:…" } },
    { "id": "key:sha256:cd34…", "type": "private-key",
      "key": { "algorithm": "alg:rsa-2048", "format": "pkcs8", "encrypted": false,
               "public_fingerprint_sha256": "…" } },
    { "id": "lib:openssl@3.0.7", "type": "library", "library": { "name": "openssl", "version": "3.0.7" } },
    { "id": "proto:tls1.2", "type": "protocol", "protocol": { "name": "TLS", "version": "1.2" } }
  ],

  "services": [
    { "id": "svc:nginx:/etc/nginx/nginx.conf", "app": "nginx",
      "version": { "value": "1.20.1", "source": "binary-string", "confidence": "high" },
      "binary": "/usr/sbin/nginx", "config_files": ["…"],
      "crypto_backend": { "library": "lib:openssl@3.0.7" },
      "endpoints": [ { "scope": "server example.co.jp:443", "usage": "tls-server" } ] }
  ],

  "occurrences": [
    { "id": "occ:…", "asset": "proto:tls1.2", "collector": "apps",
      "service": "svc:nginx:/etc/nginx/nginx.conf", "endpoint": 0,
      "usage": "tls-server",
      "state": "effective",            // configured | effective | default | capability | reference
      "confidence": "high",
      "setting": "set:…",              // 順序・層別の値・解決過程は settings[] 側に持つ
      "evidence": { "rule": "apps/nginx#ssl_protocols" } },

    { "id": "occ:…", "asset": "alg:aes-128-ecb", "collector": "source", "usage": "encryption",
      "state": "reference", "confidence": "medium",
      "location": { "kind": "file", "path": "/src/app/Crypto.java", "line": 42, "column": 17 },
      "evidence": { "rule": "source/java/jca#cipher-getinstance",
                    "api": "javax.crypto.Cipher.getInstance", "spec": "AES",
                    "note": "モード未指定のためプロバイダ既定(ECB)と解釈" } }
  ],

  "settings": [                        // 順序付き・層別の値を持つ設定項目
    { "id": "set:…", "service": "svc:nginx:/etc/nginx/nginx.conf", "scope": "server example.co.jp:443",
      "parameter": "tls.cipher-suites", "state": "effective", "confidence": "medium",
      "effective": ["suite:TLS_AES_256_GCM_SHA384", "suite:ECDHE-RSA-AES256-GCM-SHA384"],
      "layers": [                      // 各層の生の値（事実）と、合成で果たした役割
        { "layer": "app-config",  "op": "override", "raw": "HIGH:!aNULL:!MD5",
          "location": { "kind": "file", "path": "/etc/nginx/nginx.conf", "line": 41 } },
        { "layer": "os-policy",   "op": "restrict", "raw": "@SECLEVEL=2", "source": "crypto-policies:DEFAULT" }
      ] }
  ],

  "assessment": {                      // スキャン時点の評価ポリシーによる評価のスナップショット（参考値）
    "policy": "default", "policy_version": "…",
    "by_asset": { "alg:rsa-2048": { "quantum": "vulnerable", "classical": "acceptable",
                                    "references": ["NIST IR 8547", "CRYPTREC"] } }
  },

  "skipped": [ { "path": "/mnt/share", "reason": "network-fs", "detail": "nfs4" },
               { "path": "/etc/ssl/private", "reason": "permission-denied" } ],
  "coverage": { "files_examined": 0, "skipped_by_reason": { "network-fs": 1 }, "collectors": { "apps": "ok" } },
  "errors": [ ]
}
```

- 資産の型: `algorithm` / `cipher-suite` / `certificate` / `private-key` / `public-key` / `keystore`（形式、保護方式、反復回数、エントリ数）/ `library` / `protocol`。
- `location.kind`: `file` / `registry` / `certstore` / `archive-entry`（`a.war!/WEB-INF/lib/b.jar!/X.class`）等。
- **評価**: 危殆化・量子耐性の判定は用途と基準で変わる（例: SHA-1 は署名用途と HMAC 用途で扱いが異なる）ため、カタログの固定属性ではなく
  **評価ポリシー**（「資産・パラメータ・用途」の条件 → 判定・期限・根拠文書。CRYPTREC、NIST 等の複数プロファイル）としてルールに持つ。
  結果 JSON 内の `assessment` はスキャン時点の参考値で、`report` / `convert` は実行時のポリシー（`--policy`、`--rules`）で再評価し、使用したポリシーを出力に記録する。
- 大規模結果に備えストリーミングで書き出す。`skipped` が膨大な場合は理由別件数を必ず保持し、個別一覧は上限を設けて全件をログへ。
- JSON Schema をリポジトリに同梱し、`schema` の版で互換性を管理する。

変換:
- **CBOM**: CycloneDX JSON（`--cbom-version 1.6|1.7`）。`cryptographic-asset` コンポーネント＋ `evidence.occurrences`、アプリ→ライブラリ→アルゴリズムの関係は `dependencies` で表す。
  CycloneDX の出現は状態（設定済み／可能性のみ）や信頼度を持てないため、区別が必要な情報は `properties` に落とす。解決チェーン等は省略。
  カタログには CBOM の属性（パラメータセット、暗号機能、セキュリティレベル等）を持たせ、公式 JSON Schema での検証をテストに含める。
- **CSV**: 出現1件＝1行に平坦化（ホスト、資産種別、アルゴリズム、鍵長、用途、状態、場所、アプリ、評価 …）。Excel での文字化けを避けるため UTF-8 BOM 付き（オプションで BOM なし・CP932 に切替）。

### 7.3 検出ルール

- 形式は YAML。厳格に読み込む（未知のキーは拒否、値は文字列として扱い `1.20` が数値 `1.2` に化ける類の罠を避ける）。内包ルールは `go:embed`。
- YAML パーサの選定条件: 保守が続いていること、`net`・`os/exec` に依存しないこと、**エイリアス展開に上限があること**（少数のアンカーを多重参照して巨大なデータに膨らませる攻撃への耐性）。
  加えて本ツール側でも、ルールファイルのサイズ・ネスト深さ・展開後のノード数に上限を設け、ルールでアンカー／エイリアスを使う必要がないため**エイリアス自体を拒否**する。
  上限が効くことは、展開爆発を仕込んだルールファイルを使うテストで確認する。
- `--rules DIR` 指定時は既定で**内包ルールを使わず DIR のみ**を使う（挙動が一意）。`rules export` → 編集 → `--rules` の流れ。
  社内アプリのプロファイルを少数足したいだけの場合のために `--rules-mode overlay`（内包ルールに追加・上書き）も用意する。
  外部ルールの基準版がバイナリ内包版より古い場合は、ログ・結果・レポートに警告を残す。
- 版の比較方式はプロファイルで宣言する（`semver` / `openssl`（`1.1.1k`）/ `openssh`（`9.6p1`）/ `rpm` / `dpkg`）。既定値表は「版」に加え「ディストリ・パッケージリリース」を条件にできる。
- 鍵長等の導出もデータで宣言する（RSA のモジュラス長、EC の曲線、固定値）。
- ルールは宣言的データのみ。照合に使う正規表現は線形時間のエンジンで評価される。
- 読み込み時に全体を検証（スキーマ、ID 重複、カタログ参照の解決）し、エラーがあれば起動を止める。

| ファイル群 | 内容 |
|---|---|
| `catalog/algorithms.yaml` | 暗号カタログ: 正規 ID、種別（共通鍵/ハッシュ/署名/KEM/鍵交換/MAC/KDF/AEAD…）、パラメータ、**別名**（JCA 名、OpenSSL 名、OID、CNG 識別子、SSH 名 等）、CBOM 用属性 |
| `policy/*.yaml` | 評価ポリシー（7.2）: 条件 → 量子耐性・古典的安全性の判定、期限、根拠文書 |
| `catalog/tls.yaml` | 暗号スイート（IANA 名と各ライブラリでの名称、構成アルゴリズム）、グループ、署名方式 |
| `libraries/*.yaml` | ライブラリ: 識別（soname、DLL 名、版文字列パターン、シンボル→アルゴリズム対応）、既定値・対応スイート表。既定値は上流の版だけでなく**ディストリビューションのパッケージ版ごと**に持ち、ディストリによる改変（RHEL の `PROFILE=SYSTEM`、無効化されたアルゴリズム等）を反映する。該当するパッケージ版の定義がない場合は上流版の値に落とし、信頼度を下げる |
| `os/*.yaml` | OS 設定の所在（ファイル／レジストリ）と解釈、OS バージョン別既定値、標準証明書ストアの場所、ネットワーク FS 種別リスト |
| `apps/*.yaml` | アプリプロファイル（5.3） |
| `source/<lang>/*.yaml` | 言語別 API ルール、設定ファイルキー。.NET の API ルールは `source/dotnet/` に置き VB.NET・C#・PowerShell で共有 |
| `binary/*.yaml` | バイナリ内文字列・シンボルの対応 |
| `files.yaml` | 証明書・鍵・キーストアのファイル判定 |

**新しい暗号の追加**は、`catalog/algorithms.yaml` に1エントリ（ID、別名、OID）を足せば証明書・設定・ソース・バイナリの各コレクタで名前として認識される。
TLS で使う場合は `catalog/tls.yaml`（コードポイント・スイート）、ライブラリの版別対応表、評価ポリシーにも追記が要るが、いずれもデータの変更でコードの変更は不要。
カタログにない名前に出会った場合は捨てずに未知のアルゴリズムとして記録し（出力条件は 4.5）、棚卸し漏れを可視化する。

例（イメージ）:

```yaml
# catalog/algorithms.yaml
- id: ml-kem-768
  family: ML-KEM
  primitive: kem
  aliases: { oid: ["2.16.840.1.101.3.4.4.2"], openssl: ["ML-KEM-768", "MLKEM768"], jca: ["ML-KEM-768"] }
  references: ["FIPS 203"]

# apps/nginx.yaml
id: nginx
discover:
  binaries: ["nginx"]
  config_paths: { linux: ["/etc/nginx/nginx.conf", "/usr/local/nginx/conf/nginx.conf"] }
  service_flags: { config: ["-c"] }      # サービス定義（ExecStart 等）の引数から設定ファイルを特定
version: { binary_string: 'nginx/(\d+\.\d+\.\d+)' }
grammar: nginx
backend: openssl
directives:
  - name: ssl_protocols
    type: protocol-list
    scopes: [http, server]
    defaults:
      - { versions: "<1.23.4",  value: "TLSv1 TLSv1.1 TLSv1.2" }
      - { versions: ">=1.23.4", value: "TLSv1 TLSv1.1 TLSv1.2 TLSv1.3" }
  - name: ssl_ciphers
    type: cipher-list
    scopes: [http, server]
    defaults: [ { versions: "*", value: "HIGH:!aNULL:!MD5" } ]
  - name: ssl_certificate
    type: path
    role: certificate
  - name: ssl_password_file
    type: secret

# source/java/jca.yaml
- id: cipher-getinstance
  match: { call: "javax.crypto.Cipher.getInstance", capture_arg: 0 }
  interpret: jca-transformation
  usage: encryption
```

（表中の既定値は例示。実際の値は各アプリの公式文書と実物で検証して定義する。）

### 7.4 HTML レポートと集約

主対象の規模は**数百〜数千ホスト**。全ホストの明細を1つの HTML に埋め込むことはできないため、集約を前提に設計する。

- `kagiya report [-o DIR] [--lang ja|en] [--policy NAME] 入力...` → 単一 HTML（CSS/JS/データをすべて内包、外部参照なし）。入力は結果 JSON（複数可）または集約 JSON。
- `kagiya merge -o DIR 結果JSON...`（ディレクトリ指定可）→ 集約 JSON。結果ファイルを1つずつストリーミングで読み、メモリ使用量をホスト数に比例させない。
  集約 JSON 同士もさらに集約できる（部門ごとに集約 → 全社で集約、という持ち寄り運用を想定）。
- 集約の単位は「検出グループ」: （資産 × 用途 × 状態 × アプリ）ごとに、該当ホストの一覧と件数を持つ。構成の似たホストが多い大規模環境ではよく圧縮される。
  ホスト別には、要約（リスク区分別件数、OS、ラベル、スキャン日時、網羅性、ルール版）を持つ。

表示は入力に応じて切り替える:

| 入力 | 表示 |
|---|---|
| 1ホスト | サマリ（量子脆弱・非推奨・要確認の件数）、アルゴリズム別・用途別の内訳、サービス別の実効設定と各層の値、証明書一覧と有効期限、ソース／バイナリの検出一覧、**スキャンできなかった範囲**、絞り込み・検索 |
| 複数ホスト（明細を埋め込める規模） | 上記に加え、ホスト横断ビューとホスト別ドリルダウン |
| 多数ホスト／集約 JSON | 全体サマリ、ラベル別（システム・部門）の集計、ホスト × リスク区分の一覧（並べ替え・絞り込み）、アルゴリズムから利用ホストへの逆引き、証明書期限の全体分布、同一証明書・鍵の使い回し、古いルール／未完了スキャンのホスト一覧。個別ホストの明細は埋め込まず、そのホストの結果 JSON から個別レポートを作る運用とする |

- 明細を埋め込むか集約表示にするかは、データ量の上限で自動的に決め、どちらで表示しているかを画面に明示する。
- 同一ホストの異なる時点（`host.id` で判定）の差分・推移ビューは Phase 6。
- 評価はレポート生成時の評価ポリシーで再計算する。

### 7.5 ログ

- 既定 `./logs/`、`--log-dir` で変更。実行ごとに1ファイル（JSON Lines）。権限は出力と同じ。
- 記録内容: 起動条件、適用した安全策、各コレクタの開始・終了、スキップ（理由別、権限不足含む）、パースエラー、上限超過、終了サマリ。
- 標準エラー出力には進捗と要約のみ。

---

## 8. 動作環境と互換性

| OS | 対象 | 考慮点 |
|---|---|---|
| RHEL 系 8 以降（互換ディストリ含む） | amd64 / arm64 | crypto-policies、FIPS モード、`/etc/pki` 配置、SELinux 下での権限拒否（記録して継続） |
| Ubuntu 16.04 以降（Debian 系） | amd64 / arm64 | crypto-policies なし（OpenSSL/GnuTLS 各設定とライブラリ既定で解決）、`/etc/ssl` 配置、版ごとの OpenSSL 系統差（1.0.2 / 1.1.x / 3.x） |
| その他 Linux | ベストエフォート | ディストリ判定は `/etc/os-release`。未知のディストリは汎用プロファイルで動作し、その旨を記録 |
| Windows Server 2016 以降、Windows 10 以降 | amd64 | ビルド番号別の Schannel 既定値、長いパス、管理者権限なしでの縮退動作 |

- 権限: 一般ユーザーでも動作し、読めないものは記録する。網羅性のためには root / 管理者での実行を推奨（文書に明記）。
- 実行制御の考慮: `noexec` マウント、RHEL の fapolicyd、Windows の WDAC / AppLocker、SELinux 下でのジョブ実行について、利用者向け文書で設置場所と許可設定を案内する。
- Windows コンソール（CP932）での文字化けを避けるため、標準エラー出力のメッセージは ASCII のみとする。
- OS・ディストリ・版の差異はコードの分岐ではなく、可能な限りルール（`os/*.yaml`）で表現する。

---

## 9. 設計上の主な判断

### 9.1 ユーザーに相談して決定した事項（2026-11-12）

| # | 論点 | 決定 |
|---|---|---|
| A | パスワード保護されたキーストア | **パスワードは一切使わない**（機能自体を実装しない）。暗号化されて読めない部分は「未確認」として明示 |
| D | 稼働プロセス情報の利用 | **既定では読まない**。`--process-info` 明示時のみ、Linux で `/proc/<pid>/exe` と `maps` だけを読む。`environ` 等の機微な情報を含むファイルは読まない（`cmdline` も同様に扱う） |
| F | 実効値解決の順序 | 要件の順を基本形とし、**現実の挙動が異なるアプリは現実の順で解決**する。各層の生の値も記録 |
| H | レポートの規模 | **数百〜数千ホスト**を主対象とする。集約（`merge`）と集約表示を v1 の必須機能とする |

### 9.2 設計者の判断で決めた事項（異論があれば変更可能）

| # | 論点 | 本設計での既定 | 代替 |
|---|---|---|---|
| B | 既定のファイル探索範囲 | 5.5 の限定された起点（`/home` は含めない） | ローカル FS 全体を既定にする（網羅性↑・負荷↑） |
| C | `/etc/shadow` のハッシュ方式集計 | 読まない（機微なファイルを読まない方針 D に合わせる）。`login.defs`・PAM 設定から方式を得る | オプションで方式の件数のみ集計 |
| E | 外部ルール指定時の動作 | 内包ルールを完全に置換（`--rules-mode overlay` で追加・上書きも可） | overlay を既定にする |
| G | 出力先・実行ファイルが共有フォルダ上の場合 | 拒否（ローカルに置く運用を案内） | 警告のみで許容 |
| I | 評価基準の既定 | CRYPTREC 暗号リストと NIST（SP 800-131A、IR 8547）を併記 | いずれか一方 |
| J | 対象外の旧 OS（RHEL 7、Windows Server 2012 R2 以前） | 対応しない（要件どおり） | — |
| K | コンテナイメージ層の解析 | v1 対象外 | 将来フェーズ |
| L | レポートの既定言語 | 日本語（`--lang en` で英語） | 英語既定 |

---

## 10. テスト方針

- テスト駆動（期待される入出力からテストを先に書き、失敗を確認してから実装）。
- パーサ・解決ロジック: 実物の設定ファイル（ディストリ・版別の既定設定）をフィクスチャとしたゴールデンテスト。
- `safefs`・`platform` はインターフェース越しに偽のマウント表／レジストリを注入して単体テスト。
- 安全性の回帰テスト: 禁止 import 検査、バイナリのシンボル検査、ネットワーク名前空間なし＋ `strace` 下の結合テスト、出力ファイル権限、秘密値がどの出力にも現れないこと（既知の秘密値を仕込んだフィクスチャで全出力を検索）。
- ファジング: DER、PEM、キーストア、ELF/PE/class、各設定文法、字句解析器。
- 実 OS での結合テスト: RHEL 8/9、Ubuntu 16.04/20.04/24.04 のコンテナ・VM、Windows Server 2016/2022。
- 性能・負荷テスト: 大量ファイルのツリーでの CPU・I/O・メモリ・所要時間の計測と上限の検証。

---

## 11. フェーズ計画

各フェーズの終わりに動く成果物を出す。データモデル（JSON スキーマ）は Phase 3 完了まで `v0`（互換性を保証しない）とし、コレクタの実装で得た知見を反映してから `v1` として固定する。

| フェーズ | 内容 | 完了条件 |
|---|---|---|
| **0 基盤と縦切り** | リポジトリ／CI、禁止 import・`syscall` 使用箇所・シンボルの検査、CLI 骨格、`safefs`（Linux/Windows。ハンドル相対走査、ネットワーク FS 回避、除外、権限エラー記録）、Windows API ラッパ（レジストリ、ACL、ドライブ種別、優先度、Job）、優先度低下と流量制限、コアダンプ無効化、seccomp、出力権限、ログ、ルールローダ／`rules export`・`validate`、**PEM 証明書ファイル → 結果 JSON の最小の縦切り** | RHEL 8・Ubuntu 16.04・Windows Server 2016 の実機／実イメージで起動。通信なしの結合テスト（strace、ロード済みモジュール検査）が通る。負荷試験で流量制限の既定値を確定 |
| **1a 証明書・鍵** | 暗号カタログ初版、ASN.1（BER/DER）リーダ、X.509・CSR・各形式の鍵、JKS・PKCS#12（外側構造）、Linux の証明書ストア、JSON・CSV 出力 | 公開テストベクタと実ファイル群でのゴールデンテスト、ファジング |
| **1b Linux の事実収集** | OS 暗号設定、rpm DB・dpkg からのパッケージ版特定、**リンクしている暗号ライブラリの特定**（ELF の `DT_NEEDED` の解決、ライブラリ内の版文字列。実効値解決の前提となる最小限の ELF 読取）、アプリプロファイル機構、OpenSSH / nginx / Apache httpd の設定値（`configured` のみ） | 対象ディストリ各版の既定設定を正しく読める。各アプリが使う暗号ライブラリとそのパッケージ版を特定できる |
| **1c 実効値解決** | 解決モデルとフック、OpenSSL 暗号文字列展開、正解データ基盤。まず sshd で実証し、次に nginx / Apache | CI の正解データ（`sshd -T` 等）との一致 |
| **2 Windows** | Schannel・.NET 等の OS 設定、証明書ストア（レジストリ／ファイル）、IIS、HTTP.sys（形式調査を冒頭に実施）、OS ビルド別既定値 | Windows Server 2016/2019/2022 の実機で検証 |
| **3 レポート・集約・変換** | HTML レポート（単一／複数／多数ホスト）、`merge`（集約 JSON）、CBOM 変換（公式スキーマ検証）、評価ポリシー、`v1` スキーマ固定 | 数千ホスト分の合成データで、集約とレポート生成がメモリ・時間の上限内に収まる |
| **4 ソースコード解析** | 字句解析器（Java、VB.NET、C#、PowerShell、シェル）、主要 API ルール、設定ファイル、文字コード対応 | スタイル違いの同値コード群で同一結果 |
| **5 バイナリ解析** | ELF（Phase 1b の読取を拡張: 動的シンボル、静的リンクの版文字列）/ PE / .NET メタデータ / class・JAR、探索起点配下のバイナリ全般への適用 | ファジング、実バイナリ群でのテスト |
| **6 拡充・堅牢化** | アプリプロファイル拡充（Postfix、Dovecot、Tomcat、HAProxy、DB、VPN、国内で利用の多い商用ミドルウェアは要望に応じて）、時系列差分ビュー、PGP/PPK・NSS DB 等、性能試験、利用者向け文書の整備 | v1.0 |

フェーズ横断で最初の配布から行うこと: 署名付きバイナリとチェックサムの公開、ツール自身の SBOM、利用者向け文書（読み取り対象一覧、負荷と副作用の説明、通信しないことの確認手順）。

主なリスクと置き方:
- 実効値解決の正しさ（最大のリスク）→ 1c で正解データとの突き合わせを完了条件にする。
- Windows の API ラッパ自作と安全策 → Phase 0 に含め、早期に実機で検証。
- 形式パーサの自作量（BER、PKCS#12、キーストア、ELF/PE）→ 対応形式を段階的に増やし、ファジングを各フェーズの完了条件に含める。
- Go の最小対応 OS とサポート期間 → 版を固定し続けるとセキュリティ修正が止まるため、対応 OS の切り捨て方針を文書化する。

---

## 12. レビュー記録

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

---

## 13. 実装状況

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

### CI での確認（2026-11-12）

GitHub Actions の全16ジョブが成功した（リポジトリ所有者からの報告による）。これにより次の点が確認できた。

- amd64 の実カーネル（Ubuntu 22.04 / 24.04 のランナー）で、seccomp の適用、全スレッドの優先度低下、コアダンプ無効化、出力の権限、strace での通信系システムコール 0 回
- Ubuntu 16.04 / 20.04 / 24.04、UBI 8 / 9、Rocky Linux 8、Debian 13 のコンテナ（amd64）での同じ検証（strace を除く）
- Windows Server 2022 / 2025 での単体テスト（OS に依存しない部分）、ビルド、起動、`scan` が書き込まずに拒否されること

引き続き未確認: 各ディストリ本来のカーネル（RHEL 8 の 4.18、Ubuntu 16.04 の 4.4）上での動作、Windows Server 2016 / 2019、実際の NFS / SMB / autofs マウントのスキップ。

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

---

## 14. 「使われている」と「入っているだけ」の区別（2026-11-12 決定）

暗号資産が実際に使われているのか、システムに入っていて使える状態にあるだけなのかは、移行の優先度付けに直結する。
結果のデータモデルで、次の2つの軸を分けて記録する（スキーマ v0 のうちに反映する。実装は Phase 1b のアプリプロファイルとあわせて行う）。

### 軸1: 値の根拠（何を見て分かったか）

設定に明記、既定値から解決、バイナリが対応しているだけ、ソースコードに記述、ファイルとして存在、など。現在の `state` がこれにあたる。

### 軸2: 利用の確からしさ

| 段階 | 意味 | 根拠の例 |
|---|---|---|
| 稼働中 | プロセスが動いていて、そのライブラリを実際に読み込んでいる | `/proc/<pid>/exe`、`maps`（`--process-info` 指定時のみ） |
| 有効 | 起動するよう設定されたサービスが使う | systemd の有効化状態、Windows サービスの開始種別 |
| 参照あり | 有効かどうかは不明だが、設定ファイルから指されている | サーバーの設定が指す証明書・鍵のパス |
| 導入のみ | 入っているだけで、使う設定が見当たらない | パッケージは導入済みだがサービスは無効、どこからも参照されない鍵 |
| 不明 | 判断材料がない | 探索で見つけた出所不明のファイル |

出現ごとに、段階とその根拠（どのファイルのどの記述から判断したか）を記録する。
「導入のみ」も捨てない。どこからも参照されていない秘密鍵は、放置された鍵として報告する価値がある。

### 決定事項

- **サービスの有効化状態は既定で読む。** systemd は `/etc/systemd/system/` 配下のリンクの有無、Windows はレジストリのサービス定義から読める。コマンド実行もプロセス情報の読み取りも要らない。
- **ログは根拠に使わない。** 量が多く、個人情報を含み得るため。
- **表現**: 暗号スイートなど設定から分かるものは「許可されている」と表現し、「使われている」とは書かない。

### このツールでは分からないこと（結果とレポートに明示する）

- 実際にネゴシエーションされている暗号（設定から言えるのは「提示・許可されている」まで）
- 「有効」と「稼働中」の差（起動設定があっても止まっていることがあり、手動起動やソケット起動で動いていることもある）
- クライアント側の利用（定期実行されるスクリプトなどからの利用は、サービスとしては見えない）
- ソースコードに書かれた処理が、本番で動いているかどうか

### レポートでの見せ方（2026-11-12 決定）

レポートを開いたときは、「有効」以上（起動するよう設定されたサービスが使っているもの）を前面に出す。
「導入のみ」は件数つきの見出しにまとめ、クリックで開く。畳んだ部分の件数は必ず表示する。
どこからも参照されていない秘密鍵のように注意が必要なものは、畳まずに別枠で目立たせる。
CSV と CBOM には常に全件を出す。

---

## 15. 追加開発の候補（未着手）

実装の途中で出た要望・気づきのうち、今のフェーズ計画に入れていないもの。該当フェーズで画面や実装を見ながら採否を決める。

| 項目 | 内容 | 検討時期 |
|---|---|---|
| CA 証明書の署名方式別グルーピング | 信頼ストアの CA 証明書（1台あたり数百件）を、署名方式（例: SHA-256 with RSA、ECDSA with SHA-384）ごとにまとめて表示する。件数の多い「導入のみ」の一覧を把握しやすくする | Phase 3（実際の画面レイアウトを見て決める） |
| SUSE 系の rpm データベース（NDB 形式） | 現在は Berkeley DB と SQLite のみ対応 | 要望があれば |
| 外部ルールの署名検証 | ルールを書ける人は実行権限で読める情報の一部を出力に導けるため、署名で改ざんを防ぐ | Phase 6 |
| パス・Subject の仮名化オプション | 出力を社外に渡す場合の配慮 | Phase 6 |
| 国内で利用の多い商用ミドルウェアのプロファイル | WebLogic、WebSphere、HULFT など | 要望に応じて |
| ログを根拠にした「実際に使われた暗号」の把握 | 量と個人情報の懸念から v1 では行わない（14章） | v1 以降 |

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
- **TLS 1.3 のスイートは、量子計算機に対する評価を「判定できない」とする。** 鍵共有がスイートではなくグループの設定で決まり、その実効値をまだ求めていないため。

レポートの構成（1ホスト）: スキャンの概要、要点（起動するよう設定されたサービスの設定、ファイルとして見つかった証明書・鍵、調べられた範囲）、
サービスの設定（範囲ごとの実効値と求め方、判定、設定の記載）、証明書と鍵（参照されていない秘密鍵を別枠に、証明書ストアは畳んで署名の方式ごとにまとめる）、
OS とライブラリ、調べられなかった範囲、このレポートでは分からないこと、判定の基準と出典。
起動するよう設定されていないサービスと証明書ストアは畳み、件数を見出しに出す（14章の決定のとおり）。

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
| stunnel、Postfix | 未 | |
| PostgreSQL ほか（UBI にないもの） | 未 | RHEL 系の実測をどのイメージで行うかを決める必要がある |

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

差分テストで見つかった不具合: 最初の実装では、実際のスキャン結果に `haproxy` のパッケージ情報が入らず、版ごとの既定を引けていなかった
（記録対象のパッケージ名の一覧に足していなかった）。単体テストはパッケージを直接与えるため通っていた。
ルールが参照するパッケージが記録対象に入っていることを確かめるテスト（`TestRulePackagesAreRecorded`）を足して、再発を防いでいる。
