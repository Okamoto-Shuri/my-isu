#READMW

## 変更前のscoreの数値
docker run --network host -i private-isu-benchmarker /bin/benchmarker -t http://host.docker.internal -u /opt/userdata
{"pass":true,"score":1278,"success":1117,"fail":0,"messages":[]}


## 変更後のscoreの数値
docker run --network host -i private-isu-benchmarker /bin/benchmarker -t http://host.docker.internal -u /opt/userdata
{"pass":true,"score":1337,"success":1176,"fail":0,"messages":[]}


## :bulb:  ひとこと
最も効果的だった改善ポイントは、「N+1クエリの解消」「適切なインデックスの追加」「不要なDBアクセスの削減」であった 。
