from typing import List, Union, Dict, Tuple
Number = Union[int, float]
ValueList = List[Number]
LabelList = List[str]
ColorList = List[Union[str, Tuple[float]]]

from collections import Counter
from os.path import abspath, dirname, splitext, join as pjoin
import matplotlib.pyplot as plt

plt.rcParams['font.size'] = 16
OUTPUT_DIR = pjoin(dirname(abspath(__file__)), '..', 'pie')


def plot_pie(
    values: ValueList,
    labels: LabelList,
    colors: ColorList = None,
    filename: str = 'pie.pdf'
):
    """円グラフを作る
    labelごとに色を一致させたい場合は、 label_to_color を指定する

    Arguments:
        data_list {List[Number]} -- 円グラフの値（自動的に正規化がかかる）
        labels {List[str]} -- 各要素のラベル

    Keyword Arguments:
        filename {str} -- 出力ファイル名（.pdfは無くてもOK） (default: {'pie.pdf'})
        colors {List[str]} -- 色指定用のリスト（color形式 Ex. '#1f77b4' の str が入ったリスト）
    """
    if colors:
        assert len(values) == len(labels) == len(colors), '[ERROR] values, labels, colors の要素数は等しくなければならない'
    else:
        assert len(values) == len(labels), '[ERROR] values, labels の要素数は等しくなければならない'

    # filename に .pdf が無い場合に補完
    if splitext(filename)[-1] != '.pdf':
        filename += '.pdf'

    plt.close()  # 初期化。繰り返し呼び出されることを考慮している。

    # グラフプロット
    plt.pie(
        values, labels=labels, counterclock=False, startangle=90,
        colors=colors,
        wedgeprops={
            'linewidth': 3,
            'edgecolor': 'white'
        }
    )
    plt.axis('equal')  # 真円になるように設定（おそらく不要）

    # ファイルに出力
    plt.savefig(pjoin(OUTPUT_DIR, filename), bbox_inches='tight')
