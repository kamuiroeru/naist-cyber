from typing import Dict, List, Tuple, Union
from collections import defaultdict, Counter
import pandas as pd
from argparse import ArgumentParser, Namespace
from glob import glob
from itertools import cycle
from math import isnan

import matplotlib as mpl
mpl.use('Agg')
import matplotlib.pyplot as plt

from os.path import abspath, dirname, splitext, basename, join as pjoin
from sys import path
SCRIPT_PATH = dirname(abspath(__file__))
path.append(SCRIPT_PATH)

from scripts.plot import plot_pie, ValueList, LabelList
from scripts.search_nvd_records import NVD
from scripts.classes import CVSS_V3


def count_up_av(
    list_or_df: Union[pd.DataFrame, List[str]],
    cve_id_col_name: str = 'CVE_ID',
    nvd: NVD = None
) -> [Dict[str, Counter], Counter]:
    """CVE_ID のリストから Attack Vector を集計する

    Args:
        list_or_df (Union[pd.DataFrame, List[str]]): CVE_ID のリストか それを含む DataFrame
        cve_id_col_name (str, optional): DataFrame の CVE_ID のColumn name. Defaults to 'CVE_ID'.
        nvd (NVD, optional): nvd を initialize してたら読み込んで使える（再読み込みが不要）. Defaults to None.

    Returns:
        [Dict[str, Counter], Counter]: 年ごとの集計, 一括の集計
    """
    year2avs: Dict[str, List[str]] = defaultdict(list)
    all_avs: List[str] = []

    if nvd is None:
        nvd = NVD()

    if isinstance(list_or_df, pd.DataFrame):
        cve_id_list = list_or_df[cve_id_col_name]
    else:
        cve_id_list = list_or_df

    for cve_id in cve_id_list:
        cve = nvd.get_item(cve_id)
        year: str = cve_id.split('-')[1]
        cvss_v3 = cve.impact.get('V3', CVSS_V3({}))
        av_v3 = cvss_v3.attackVector
        # av_v2 = cve.impact['V2'].attackVector
        if av_v3 == '':
            av_v3 = '"None"'
        year2avs[year].append(av_v3)
        all_avs.append(av_v3)

    counted_y2a = {year: Counter(avs) for year, avs in year2avs.items()}
    counted_all_av = Counter(all_avs)

    return counted_y2a, counted_all_av


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
        year: str = record[cve_id_col_name].split('-')[1]
        if isinstance(record[cwe_col_name], float):  # nan の場合があるので、除去
            cwes = []
        else:
            cwes: List[str] = record.CWE.split('|')
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


# CWE の情報リンクのテンプレート
template_cwe = 'https://cwe.mitre.org/data/definitions/{}.html'
template_cwe_jvn = 'https://jvndb.jvn.jp/ja/cwe/CWE-{}.html'


def export_cwe_info(cwes: List[Union[str, Tuple[str, int]]], out_path: str):
    """CWEの詳細ページリンクを出力する .txt

    Arguments:
        cwes {List[Union[str, Tuple[str, int]]]} -- CWE-ID が入ったリスト, (cwe_id, 出現回数) の Tupleが入ったリストも可能
        out_path {str} -- 出力先。 Ex. 'output/cwe_most_common_9.txt'
    """

    with open(out_path, 'w') as f:
        for elem in cwes:
            print(elem)
            cwe = elem[0] if isinstance(elem, tuple) else elem
            cwe_id = cwe.split('-')[1]
            f.write(
                str(elem) + '\n' \
                + '    ' + template_cwe.format(cwe_id) + '\n' \
                + '    ' + template_cwe_jvn.format(cwe_id) + '\n' \
            )


# 出現頻度上位の CWE に色付けする際の色
tab10 = plt.get_cmap('tab10')
top_color = [tab10(i) for i in list(range(7)) + list(range(8, 10))]  # tab10 から灰色を除いた 9 色
gray = cycle(['#343d46','#4f5b66','#65737e','#a7adba','#c0c5ce'])  # 上位以外の色


def get_color_convertor(
    cwe_id_to_count: dict,
    ignore_noinfo_other: bool = True,
    export_top9_detail: bool = False,
) -> dict:
    """CWE_ID ごとのグラフ表示色 を生成する。
    出現頻度上位9こ には 特定の色を、それ以外には 5通りの濃淡を使い回す灰色を割り当てる。

    Arguments:
        cwe_id_2_count {dict} -- key: value = CWE_ID: 出現個数 となっている dict

    Keyword Arguments:
        ignore_noinfo_other {bool} -- 出現頻度上位に NVD-CWE-noinfo と NVD-CWE-other を含めない (default: {True})
        export_top9_detail {bool} -- 出現頻度上位9項目の詳細を output/cwe_most_common_9.txt に吐き出す  (default: {False})
    """

    # 全ての項目をランダムに灰色にする（5色を使い回すので重複は出るが問題ない）
    cwe_id_to_color = {key: next(gray) for key, _ in cwe_id_to_count.items()}

    # 出現頻度上位9 を抽出する
    most_common: List[Tuple[str, int]] = sorted(cwe_id_to_count.items(), key=lambda elem: elem[1], reverse=True)
    if ignore_noinfo_other:
        most_common11 = most_common[:9+2]  # noinfo と other が含まれてるかもしれないので余分に抽出
        most_common9 = list(filter(lambda x: x[0] not in {'NVD-CWE-noinfo', 'NVD-CWE-Other'}, most_common11))[:9]
    else:
        most_common9 = most_common[:9]

    for lc, elem in enumerate(most_common9):
        # 割り当て
        cwe_id = elem[0]
        cwe_id_to_color[cwe_id] = top_color[lc]

    if export_top9_detail:
        export_cwe_info(most_common9, pjoin(SCRIPT_PATH, 'output', 'cwe_most_common_9.txt'))

    return cwe_id_to_color


def plot_pie_by_output():
    """outputディレクトリにある csv （複数可） を 使って 円グラフを生成する。
    """
    csv_list = glob(pjoin(SCRIPT_PATH, 'output', '*.csv'))
    dfs = [pd.read_csv(csv, index_col=0) for csv in csv_list]
    df_concat = pd.concat(dfs)

    # 年ごとの集計
    counted_y2c, counted_all_cwe = count_up_cwe(df_concat)
    ## 色を固定するための辞書を生成する
    cwe_id_to_color = get_color_convertor(counted_all_cwe, export_top9_detail=True)

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


def plot_yearwise_norm_stacked_bar_by_output(ignore_noinfo_other: bool = True):
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
    if ignore_noinfo_other:
        if 'NVD-CWE-noinfo' in sort_index:
            nvd_cwe_noinfo = sort_index['NVD-CWE-noinfo']
            sort_index = sort_index.drop('NVD-CWE-noinfo')
            sort_index['NVD-CWE-noinfo'] = nvd_cwe_noinfo
        if 'NVD-CWE-Other' in sort_index:
            nvd_cwe_other = sort_index['NVD-CWE-Other']
            sort_index = sort_index.drop('NVD-CWE-Other')
            sort_index['NVD-CWE-Other'] = nvd_cwe_other
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
    plt.xlabel('Year')
    plt.ylabel('Gross of CVE')
    plt.savefig(pjoin(SCRIPT_PATH, 'graph', 'bar', 'yearwise_stacked.pdf'), bbox_inches='tight')

    # 100% 積み上げグラフのプロット
    plt.close()  # 念の為初期化
    df_norm.plot.bar(stacked=True, color=colors)
    plt.legend(legend_handles[::-1], legend_texts[::-1], bbox_to_anchor=(1.05, 1), loc='upper left', borderaxespad=0)
    plt.xlabel('Year')
    plt.ylabel('Rate of CVE')
    plt.savefig(pjoin(SCRIPT_PATH, 'graph', 'bar', 'yearwise_norm_stacked.pdf'), bbox_inches='tight')


def plot_categorywise_norm_stacked_bar_by_output(ignore_noinfo_other: bool = True):
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
    if ignore_noinfo_other:
        if 'NVD-CWE-noinfo' in sort_index:
            nvd_cwe_noinfo = sort_index['NVD-CWE-noinfo']
            sort_index = sort_index.drop('NVD-CWE-noinfo')
            sort_index['NVD-CWE-noinfo'] = nvd_cwe_noinfo
        if 'NVD-CWE-Other' in sort_index:
            nvd_cwe_other = sort_index['NVD-CWE-Other']
            sort_index = sort_index.drop('NVD-CWE-Other')
            sort_index['NVD-CWE-Other'] = nvd_cwe_other
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
    plt.xlabel('Category')
    plt.ylabel('Gross of CVE')
    plt.savefig(pjoin(SCRIPT_PATH, 'graph', 'bar', 'categorywise_stacked.pdf'), bbox_inches='tight')

    # 100% 積み上げグラフのプロット
    plt.close()  # 念の為初期化
    df_norm.plot.bar(stacked=True, color=colors)
    plt.legend(legend_handles[::-1], legend_texts[::-1], bbox_to_anchor=(1.05, 1), loc='upper left', borderaxespad=0)
    plt.xlabel('Category')
    plt.ylabel('Rate of CVE')
    plt.savefig(pjoin(SCRIPT_PATH, 'graph', 'bar', 'categorywise_norm_stacked.pdf'), bbox_inches='tight')


av_labels = ['NETWORK', 'ADJACENT_NETWORK', 'LOCAL', 'PHYSICAL', '"None"']
colors_for_av = {label: top_color[lc] for lc, label in enumerate(av_labels)}
colors_for_av['"None"'] = next(gray)
nvd = NVD()

def plot_av_yearwise_norm_stacked_bar_by_output(ignore_noinfo_other: bool = True):
    """
    Attack Vector の
    outputディレクトリにある csv （複数可） を 使って 100% 積み上げグラフを生成する。（年ごとのみ）
    """

    # データを読み込む
    csv_list = glob(pjoin(SCRIPT_PATH, 'output', '*.csv'))
    dfs = [pd.read_csv(csv, index_col=0) for csv in csv_list]
    df_concat = pd.concat(dfs)

    counted_y2a, counted_all_avs = count_up_av(df_concat, nvd=nvd)

    # 積み上げグラフは pandas.plot.bar で作ると楽なので、DataFrameを作る
    df = pd.DataFrame()  # 通常の積み上げグラフ用
    df_norm = pd.DataFrame()  # 正規化積み上げグラフ用
    for year, av in counted_y2a.items():
        series = pd.Series(av, name=year)
        df = df.append(series)
        series = series.apply(lambda x: x / series.sum())  # 正規化
        df_norm = df_norm.append(series)

    # CWE を出現頻度順に、年順にプロットするために DF をソート
    sort_index = pd.Series(counted_all_avs).sort_values()[::-1]
    df = df[(label for label in av_labels if label in df.columns)]  # columns を降順でソート
    df = df.sort_index()  # records を 昇順（年代順）でソート
    df_norm = df_norm[(label for label in av_labels if label in df.columns)]  # columns を降順でソート
    df_norm = df_norm.sort_index()  # records を 昇順（年代順）でソート

    # 普通の積み上げグラフのプロット
    plot_return = df.plot.bar(stacked=True, color=[colors_for_av[label] for label in df.columns])
    # 色付きのみ凡例を降順で並べたいので設定を上書き
    legend_texts = [elem.get_text() for elem in plot_return.legend().texts]
    legend_handles = plot_return.legend().legendHandles
    ## 凡例の設定を上書き
    plt.legend(legend_handles[::-1], legend_texts[::-1], bbox_to_anchor=(1.05, 1), loc='upper left', borderaxespad=0)
    plt.xlabel('Year')
    plt.ylabel('Gross of Attack Vector')
    plt.savefig(pjoin(SCRIPT_PATH, 'graph', 'bar', 'yearwise_av_stacked.pdf'), bbox_inches='tight')

    # 100% 積み上げグラフのプロット
    plt.close()  # 念の為初期化
    df_norm.plot.bar(stacked=True, color=[colors_for_av[label] for label in df.columns])
    plt.legend(legend_handles[::-1], legend_texts[::-1], bbox_to_anchor=(1.05, 1), loc='upper left', borderaxespad=0)
    plt.xlabel('Year')
    plt.ylabel('Rate of Attack Vector')
    plt.savefig(pjoin(SCRIPT_PATH, 'graph', 'bar', 'yearwise_av_norm_stacked.pdf'), bbox_inches='tight')


def plot_av_categorywise_norm_stacked_bar_by_output(ignore_noinfo_other: bool = True):
    """
    Attack Vector の
    outputディレクトリにある csv （複数可） を 使って 100% 積み上げグラフを生成する。（csvファイルごとのみ）
    """

    # データを読み込む
    csv_list = glob(pjoin(SCRIPT_PATH, 'output', '*.csv'))
    dfs = [pd.read_csv(csv, index_col=0) for csv in csv_list]
    df_concat = pd.concat(dfs)

    counted_y2a, counted_all_avs = count_up_av(df_concat, nvd=nvd)

    # 積み上げグラフは pandas.plot.bar で作ると楽なので、DataFrameを作る
    df = pd.DataFrame()  # 通常の積み上げグラフ用
    df_norm = pd.DataFrame()  # 正規化積み上げグラフ用
    for csv, df_category in zip(csv_list, dfs):
        _, category_av = count_up_av(df_category, nvd=nvd)
        series = pd.Series(category_av, name=splitext(basename(csv))[0])
        df = df.append(series)
        series = series.apply(lambda x: x / series.sum())  # 正規化
        df_norm = df_norm.append(series)

    # CWE を出現頻度順に、年順にプロットするために DF をソート
    sort_index = pd.Series(counted_all_avs).sort_values()[::-1]
    df = df[(label for label in av_labels if label in df.columns)]  # columns を降順でソート
    df = df.sort_index()  # records を 昇順（年代順）でソート
    df_norm = df_norm[(label for label in av_labels if label in df.columns)]  # columns を降順でソート
    df_norm = df_norm.sort_index()  # records を 昇順（年代順）でソート

    # 普通の積み上げグラフのプロット
    plot_return = df.plot.bar(stacked=True, color=[colors_for_av[label] for label in df.columns])
    # 凡例を降順で表示したい
    legend_texts = [elem.get_text() for elem in plot_return.legend().texts]
    legend_handles = plot_return.legend().legendHandles
    ## 凡例の設定を上書き
    plt.legend(legend_handles[::-1], legend_texts[::-1], bbox_to_anchor=(1.05, 1), loc='upper left', borderaxespad=0)
    plt.xlabel('Category')
    plt.ylabel('Gross of Attack Vector')
    plt.savefig(pjoin(SCRIPT_PATH, 'graph', 'bar', 'categorywise_av_stacked.pdf'), bbox_inches='tight')

    # 100% 積み上げグラフのプロット
    plt.close()  # 念の為初期化
    df_norm.plot.bar(stacked=True, color=[colors_for_av[label] for label in df.columns])
    plt.legend(legend_handles[::-1], legend_texts[::-1], bbox_to_anchor=(1.05, 1), loc='upper left', borderaxespad=0)
    plt.xlabel('Category')
    plt.ylabel('Rate of Attack Vector')
    plt.savefig(pjoin(SCRIPT_PATH, 'graph', 'bar', 'categorywise_av_norm_stacked.pdf'), bbox_inches='tight')


if __name__ == "__main__":
    print('plotting pie ...')
    plot_pie_by_output()
    print('plotting yearwise stacked bar ...')
    plot_yearwise_norm_stacked_bar_by_output()
    print('plotting categorywise stacked bar ...')
    plot_categorywise_norm_stacked_bar_by_output()
    print('plotting Attack Vector yearwise stacked bar ...')
    plot_av_yearwise_norm_stacked_bar_by_output()
    print('plotting Attack Vector categorywise stacked bar ...')
    plot_av_categorywise_norm_stacked_bar_by_output()
