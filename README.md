# free-wifi-auth
![](https://github.com/yoneyan/free-wifi-auth/workflows/Go/badge.svg)

## 実装状況
|内容|status|
|---|---|
|web認証|OK|
|firewall操作|OK|
|時間制御|OK|
|ログ生成機能|NG|

現時点最低限の機能は実装済み  
また、現時点では問題が多々あるので実用段階ではない

### 問題点
 **GitHubのProjectに訂正箇所を記しています**

### Captive Portal認証
|OS|認証可能|備考|
|---|---|---|
|Android|OK|完全対応|
|iOS|△|ページ移動ができない|
|Chrome OS|OK|完全対応|
|Windows|?|未確認|
|Mac|?|未確認|

## 実行方法
```
git clone https://github.com/yoneyan/free-wifi-auth
cd free-wifi-auth
go get .
go build .
sudo free-wifi-auth
```
接続ログとしてclient.logに保存されます。(作成されないバグがあり。修正予定)  


## テスト用コマンド
|コマンド|内容|
|---|---|
|start|nftablesの初期化|
|end|サーバの停止&nftablesのfreewifi tableの削除|
|record|172.16.100.1のIPアドレスをclientdataにデータとして入れる|
|read|clientdataに入っている値をすべて表示|

### ファイル構造
|ファイル名|内容|
|---|---|
|auth.go|web認証|
|config.go|コンフィ読み取り|
|data.go|データ整形|
|firewall.go|ファイアウォール操作|
|timer.go|周期実行用|
|web.go|webサーバ|

### FAQ
#### Captive Portalが出ないとき
* DNSサーバが起動していない  
* DHCPサーバが起動していない  
可能性が考えられるので確認してください。  
