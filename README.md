# free-wifi-auth
![](https://github.com/yoneyan/free-wifi-auth/workflows/Go/badge.svg)
## 実装状況
|内容|status|
|---|---|
|web認証|OK|
|firewall操作|NG|
|時間制御|OK|
## 実行方法
```
git clone https://github.com/yoneyan/free-wifi-auth
cd free-wifi-auth
go build .
sudo free-wifi-auth
```
## テスト用コマンド


### ファイル構造
|ファイル名|内容|
|---|---|
|auth.go|web認証|
|data.go|データ整形|
|firewall.go|ファイアウォール操作|
|reject.go|インターネットアクセスの強制切断用 <-最終的に削除予定|
|timer.go|周期実行用|
|web.go|webサーバ|

