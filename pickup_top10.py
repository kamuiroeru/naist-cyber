from typing import List

from glob import glob
import pandas as pd
from os.path import abspath, dirname, splitext, basename, join as pjoin
from sys import path
SCRIPT_PATH = dirname(abspath(__file__))
path.append(SCRIPT_PATH)

from scripts.search_nvd_records import NVD
from scripts.classes import CVE_Item, CVSS_V3, CVSS_V2

nvd = NVD()

# データを読み込む
csv_list = glob(pjoin(SCRIPT_PATH, 'output', '*.csv'))
dfs = [pd.read_csv(csv, index_col=0) for csv in csv_list]
df_concat = pd.concat(dfs)

df_concat = df_concat.fillna(0)


def sort_function(elem: CVE_Item) -> tuple:
    """CVE_Item のリスト をソートするための関数
    """
    cvss_v3: CVSS_V3 = elem.impact.get('V3', CVSS_V3({}))
    cvss_v2: CVSS_V2 = elem.impact.get('V2', CVSS_V3({}))

    # ソートする順番、- を付けて降順ソートにしている
    tier1 = -(cvss_v3.baseScore + cvss_v2.baseScore)
    tier2 = -cvss_v3.baseScore

    return tier1, tier2


def to_dataframe(cve_items: List[CVE_Item]) -> pd.DataFrame:
    list_for_df = []
    for elem in cve_items:
        cve_id = elem.id
        description = elem.overview
        cvss_v3: CVSS_V3 = elem.impact.get('V3', CVSS_V3({}))
        cvss_v2: CVSS_V2 = elem.impact.get('V2', CVSS_V3({}))
        d = {
            'CVE': cve_id,
            'Description': description.replace('\n', '<br>'),
            'CVSS_V3': cvss_v3.baseScore,
            'CVSS_V2': cvss_v2.baseScore,
            'CWE': '|'.join(elem.vulnerability_type)
        }
        list_for_df.append(d)

    return pd.DataFrame(list_for_df)


cve_items: List[CVE_Item] = [nvd.get_item(cve_id) for cve_id in df_concat['CVE_ID']]
vul_top10 = to_dataframe(sorted(cve_items, key=sort_function)).iloc[:10]

vul_top10.to_csv(pjoin(SCRIPT_PATH, 'output', 'vul_top10.tsv'), sep='\t', index=None)
