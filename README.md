# サイバーセキュリティ Assignment1用 調査補助ツール
以下のことができます。
- CVE を検索して該当する CVE-ID の リストを取得する
- NIST NVD データをもとに CWE や CVSS を抽出する
- CWE を集計して 円グラフ と 積み上げ棒グラフを生成する
- CVSS の値をもとに、 脆弱性を 10個 ピックアップする (Question 3.2)
- CAPEC と CWE の関係を調査する

![Rate of CVE by Year](https://github.com/kamuiroeru/naist-cyber/blob/example/graph/bar/yearwise_norm_stacked.svg?raw=true)
![Rate of CVE by Category](https://github.com/kamuiroeru/naist-cyber/blob/example/graph/bar/categorywise_norm_stacked.svg?raw=true)

## requirements
- python 3.6>
    - pandas
    - requests
    - matplotlib
    - tqdm
    - lxml
    - openpyxl
    - xlsxwriter
- Internet Connection: CVE の検索と NIST CVD の Data feeds をダウンロードするために必要です。
- 最低で 50MB 程度の空き領域: CVD の データベースを保存するために必要です。
    - csv と xlsx と pdf を保存するために 追加で 50MB ほどあると安心です。

## How To Use
### 脆弱性のリストアップ
`Thunderbird` の脆弱性についてリストアップする場合、まず以下を実行します。
※ 最初期の実行では、 NVD Data Feeds をダウンロードし、データベース(実際はただのdictですが)を構築するので、2分ほど時間がかかります。

```sh
$ python listup.py Thunderbird
```

[`output/`](output/) ディレクトリに、 `Thunderbird.csv` と `Thunderbird.xlsx` ができます。
(References のURL が多すぎると Warning が出ますが気にしないでOKだと思います。)

出力ファイル名を変更したい場合は、 `-o` オプションが使えます。

### CWEの集計をプロット

```sh
$ python plot_output.py
```

を実行すると、 [`graph/pie/`](graph/pie/) ディレクトリに年ごと、 CSV ごとの 円グラフ が、
[`graph/bar/`](graph/bar/) ディレクトリに年ごと、 CSV ごとの 積み上げ棒グラフ ができます。
これらのグラフでは、出現頻度 TOP9 の CWE が色付けされており、
これらについての詳細（CWE_ID, 出現回数、CWE詳細ページのリンク英語版&日本語版）は
[`output/cwe_most_common_9.txt`](output/cwe_most_common_9.txt) に出力されます。

### CVSSのスコア順に top 10 をピックアップ

```sh
$ python pickup_top10.py
```

を実行すると CVSS のスコアで順位づけしたTOP10が `output/vul_top10.tsv` に出力されます。順位づけは、 CVSS_V3/V2 baseScore の和 でソートし、同じ値の場合は CVSS_V3 baseScore でソートして求めています。（[`pickup_top10.py`](pickup_top10.py) の `sort_function` を参照）

### CAPEC と CWE の関連を調べる
例えば、 `CWE-20` に関連する CAPEC を調べたい場合、

```sh
$ python -i search_attack.py --update # 初回のみ
$ python -i search_attack.py # 2回目以降
```

で python インタプリタを起動し、

```python
>>> cwe_id = '20'
>>> capec_items = capec.get_capec_items_related_cwe(cwe_id)
>>> extract_ids(capec_items)
['3', '7', '8', '9', '10', '13', '14', '22', '23', '24', '28', '31', '42', '43', '45', '46', '47', '52', '53', '63', '64', '66', '67', '71', '72', '73', '78', '79', '80', '81', '83', '85', '88', '101', '104', '108', '109', '110', '120', '135', '136', '153', '182', '209', '230', '231', '250', '261', '267', '473', '588']
```

のように抽出できます。
