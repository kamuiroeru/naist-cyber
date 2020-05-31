from typing import Dict, List, Tuple
from collections import defaultdict, Counter
import pandas as pd
from argparse import ArgumentParser, Namespace
from glob import glob
from itertools import cycle

import matplotlib as mpl
mpl.use('Agg')
import matplotlib.pyplot as plt

from os.path import abspath, dirname, splitext, basename, join as pjoin
from sys import path
SCRIPT_PATH = dirname(abspath(__file__))
path.append(SCRIPT_PATH)

from scripts.plot import plot_pie, ValueList, LabelList


def count_up_cwe(
    df: pd.DataFrame,
    cve_id_col_name: str = 'CVE_ID',
    cwe_col_name: str = 'CWE'
) -> [Dict[str, Counter], Counter]:
    """指定した DataFrame の CWE を集計する。年ごとの集計と一括の集計を返す

    Arguments:
        df {pd.DataFrame} -- pandas DataFrame

    Keyword Arguments:
        cve_id_col_name {str} -- CVE ID を持つ Column Name (default: {'CVE_ID'})
        cwe_col_name {str} -- CWE ID を持つ Column Name (default: {'CWE'})

    Returns:
        [Dict[str, Counter], Counter] -- 年ごとの集計, 一括の集計
    """

    year2cwes: Dict[str, List[str]] = defaultdict(list)
    all_cwes: List[str] = []

    for idx, record in df.iterrows():
        year: str = record.CVE_ID.split('-')[1]
        cwes: List[str] = record.CWE.split('\n')
        year2cwes[year].extend(cwes)
        all_cwes.extend(cwes)

    counted_y2c = {year: Counter(cwes) for year, cwes in year2cwes.items()}
    counted_all_cwe = Counter(all_cwes)

    return counted_y2c, counted_all_cwe


def split_data_label_from_counter(counter: Counter) -> [ValueList, LabelList]:
    """Counter Object から 円グラフを作るのに必要な
    データリスト と ラベルリスト を生成する。

    Arguments:
        counter {Counter} -- Counter Object

    Returns:
        [DataList, DataLabel] -- データリスト、 ラベルリスト
    """
    value_list, label_list = [], []
    for key, value in sorted(counter.items(), key=lambda x: x[1], reverse=True):
        value_list.append(value)
        label_list.append(key)
        # label_list.append(key.split('-')[-1])  # CWE-200 の 200 だけ抽出

    return value_list, label_list

# 出現頻度上位の CWE に色付けする際の色
tab10 = plt.get_cmap('tab10')
top_color = [tab10(i) for i in list(range(7)) + list(range(8, 10))]  # tab10 から灰色を除いた 9 色
gray = cycle(['#343d46','#4f5b66','#65737e','#a7adba','#c0c5ce'])  # 上位以外の色

# CWE の情報リンクのテンプレート
template_cwe = 'https://cwe.mitre.org/data/definitions/{}.html'
template_cwe_jvn = 'https://jvndb.jvn.jp/ja/cwe/CWE-{}.html'


def plot_pie_by_output():
    """outputディレクトリにある csv （複数可） を 使って 円グラフを生成する。
    """
    csv_list = glob(pjoin(SCRIPT_PATH, 'output', '*.csv'))
    dfs = [pd.read_csv(csv, index_col=0) for csv in csv_list]
    df_concat = pd.concat(dfs)

    # 年ごとの集計
    counted_y2c, counted_all_cwe = count_up_cwe(df_concat)
    ## 色を固定するための処理を入れる
    ### 全ての項目をランダムに灰色にする（5色を使い回すので重複は出るが問題ない）
    cwe_id_to_color = {key: next(gray) for key, _ in counted_all_cwe.items()}
    ### 出現頻度 top 9 に、matplotlib 標準色を割り当てる（上書きする）
    most_common_9: List[Tuple[str, int]] = counted_all_cwe.most_common(9)
    with open(pjoin(SCRIPT_PATH, 'output', 'cwe_most_common_9.txt'), 'w') as f:
        for lc, elem in enumerate(most_common_9):
            # 上位 9 CWE を表示
            cwe_id = elem[0].split('-')[1]
            print(elem)
            f.write(
                str(elem) + '\n' \
                + '    ' + template_cwe.format(cwe_id) + '\n' \
                + '    ' + template_cwe_jvn.format(cwe_id) + '\n' \
            )
            # 割り当て
            mc_cwe_id = elem[0]
            cwe_id_to_color[mc_cwe_id] = top_color[lc]

    for year, counter in counted_y2c.items():
        vl, ll = split_data_label_from_counter(counter)
        cl = [cwe_id_to_color[label] for label in ll]
        plot_pie(vl, ll, colors=cl, title=year, filename=year)

    # csv ファイルごとの集計
    for csv, df in zip(csv_list, dfs):
        name = splitext(basename(csv))[0]
        _, counted_all_cwe = count_up_cwe(df)
        vl, ll = split_data_label_from_counter(counted_all_cwe)
        cl = [cwe_id_to_color[label] for label in ll]
        plot_pie(vl, ll, colors=cl, title=name, filename=name)


def plot_yearwise_norm_stacked_bar_by_output():
    """outputディレクトリにある csv （複数可） を 使って 100% 積み上げグラフを生成する。（年ごとのみ）
    """

    # データを読み込む
    csv_list = glob(pjoin(SCRIPT_PATH, 'output', '*.csv'))
    dfs = [pd.read_csv(csv, index_col=0) for csv in csv_list]
    df_concat = pd.concat(dfs)

    counted_y2c, counted_all_cwe = count_up_cwe(df_concat)

    # 積み上げグラフは pandas.plot.bar で作ると楽なので、DataFrameを作る
    df = pd.DataFrame()  # 通常の積み上げグラフ用
    df_norm = pd.DataFrame()  # 正規化積み上げグラフ用
    for year, cwes in counted_y2c.items():
        series = pd.Series(cwes, name=year)
        df = df.append(series)
        series = series.apply(lambda x: x / series.sum())  # 正規化
        df_norm = df_norm.append(series)

    # CWE を出現頻度順に、年順にプロットするために DF をソート
    sort_index = pd.Series(counted_all_cwe).sort_values()[::-1]
    df = df[sort_index.index]  # columns を降順でソート
    df = df.sort_index()  # records を 昇順（年代順）でソート
    df_norm = df_norm[sort_index.index]  # columns を降順でソート
    df_norm = df_norm.sort_index()  # records を 昇順（年代順）でソート

    # CWE ごとに 色を固定する ための前処理
    # 出現頻度の上位 9 CWE だけ色付き、ほかは灰色
    colors = top_color.copy() + [next(gray) for key in range(len(df.columns) - 9)]

    # 普通の積み上げグラフのプロット
    plot_return = df.plot.bar(stacked=True, color=colors)
    ## 色付きのみ凡例を入れたいので、設定のための要素をゴリ押しで抽出
    legend_texts = [elem.get_text() for elem in plot_return.legend().texts[:9]]
    legend_handles = plot_return.legend().legendHandles[:9]
    ## 凡例の設定を上書き
    plt.legend(legend_handles[::-1], legend_texts[::-1], bbox_to_anchor=(1.05, 1), loc='upper left', borderaxespad=0)
    plt.savefig(pjoin(SCRIPT_PATH, 'graph', 'bar', 'yearwise_stacked.pdf'), bbox_inches='tight')

    # 100% 積み上げグラフのプロット
    plt.close()  # 念の為初期化
    df_norm.plot.bar(stacked=True, color=colors)
    plt.legend(legend_handles[::-1], legend_texts[::-1], bbox_to_anchor=(1.05, 1), loc='upper left', borderaxespad=0)
    plt.savefig(pjoin(SCRIPT_PATH, 'graph', 'bar', 'yearwise_norm_stacked.pdf'), bbox_inches='tight')


def plot_categorywise_norm_stacked_bar_by_output():
    """outputディレクトリにある csv （複数可） を 使って 100% 積み上げグラフを生成する。（csvファイルごとのみ）
    """

    # データを読み込む
    csv_list = glob(pjoin(SCRIPT_PATH, 'output', '*.csv'))
    dfs = [pd.read_csv(csv, index_col=0) for csv in csv_list]
    df_concat = pd.concat(dfs)

    counted_y2c, counted_all_cwe = count_up_cwe(df_concat)

    # 積み上げグラフは pandas.plot.bar で作ると楽なので、DataFrameを作る
    df = pd.DataFrame()  # 通常の積み上げグラフ用
    df_norm = pd.DataFrame()  # 正規化積み上げグラフ用
    for csv, df_category in zip(csv_list, dfs):
        _, category_cwe = count_up_cwe(df_category)
        series = pd.Series(category_cwe, name=splitext(basename(csv))[0])
        df = df.append(series)
        series = series.apply(lambda x: x / series.sum())  # 正規化
        df_norm = df_norm.append(series)

    # CWE を出現頻度順に、年順にプロットするために DF をソート
    sort_index = pd.Series(counted_all_cwe).sort_values()[::-1]
    df = df[sort_index.index]  # columns を降順でソート
    df = df.sort_index()  # records を 昇順（年代順）でソート
    df_norm = df_norm[sort_index.index]  # columns を降順でソート
    df_norm = df_norm.sort_index()  # records を 昇順（年代順）でソート

    # CWE ごとに 色を固定する ための前処理
    # 出現頻度の上位 9 CWE だけ色付き、ほかは灰色
    colors = top_color.copy() + [next(gray) for key in range(len(df.columns) - 9)]

    # 普通の積み上げグラフのプロット
    plot_return = df.plot.bar(stacked=True, color=colors)
    ## 色付きのみ凡例を入れたいので、設定のための要素をゴリ押しで抽出
    legend_texts = [elem.get_text() for elem in plot_return.legend().texts[:9]]
    legend_handles = plot_return.legend().legendHandles[:9]
    ## 凡例の設定を上書き
    plt.legend(legend_handles[::-1], legend_texts[::-1], bbox_to_anchor=(1.05, 1), loc='upper left', borderaxespad=0)
    plt.savefig(pjoin(SCRIPT_PATH, 'graph', 'bar', 'categorywise_stacked.pdf'), bbox_inches='tight')

    # 100% 積み上げグラフのプロット
    plt.close()  # 念の為初期化
    df_norm.plot.bar(stacked=True, color=colors)
    plt.legend(legend_handles[::-1], legend_texts[::-1], bbox_to_anchor=(1.05, 1), loc='upper left', borderaxespad=0)
    plt.savefig(pjoin(SCRIPT_PATH, 'graph', 'bar', 'categorywise_norm_stacked.pdf'), bbox_inches='tight')

if __name__ == "__main__":
    plot_pie_by_output()
    plot_yearwise_norm_stacked_bar_by_output()
    plot_categorywise_norm_stacked_bar_by_output()
