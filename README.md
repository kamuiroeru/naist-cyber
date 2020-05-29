# サイバーセキュリティ Assignment1
## requirements
- python 3.6>
    - pandas
    - requests
    - matplotlib
    - tqdm
- Internet Connection: CVE の検索と NIST CVD の Data feeds をダウンロードするために必要です。
- 最低で 50MB 程度の空き領域: CVD の データベースを保存するために必要です。
    - csv と xlsx と pdf を保存するために 追加で 50MB ほどあると安心です。

## How To Use
`Thunderbird` の脆弱性についてリストアップする場合、まず以下を実行します。
※ 最初期の実行では、 NVD Data Feeds をダウンロードし、データベース(実際はただのdictですが)を構築するので、2分ほど時間がかかります。

```sh
$ python listup.py Thunderbird
```

`output/` ディレクトリに、 `result.csv` と `result.xlsx` ができます。
(References のURL が多すぎると Warning が出ますが気にしないでOKだと思います。)

また、

```sh
$ python analyze_result.py
```

を実行すると、 `pie/` ディレクトリに年ごと、 CSV ごとの 円グラフ ができます。この円グラフでは、出現頻度 TOP10 の CWE が色付けされており、これらについての詳細（CWE_ID, 出現回数、CWE詳細ページのリンク英語版&日本語版）は `output/cwe_most_common_10.txt` に出力されます。
