from typing import List, Union
import pandas as pd
from argparse import ArgumentParser, Namespace

from os import chdir
from os.path import dirname, abspath, join as pjoin

SCRIPT_PATH = dirname(abspath(__file__))
# どこから実行してもOK
chdir(SCRIPT_PATH)

from scripts.classes import CVE_Item, CVSS_V3, CVSS_V2
from scripts.search_nvd_records import (
    NVD, search_CVE_records
)

nvd = NVD()
OUTPUT_DIR = pjoin(SCRIPT_PATH, 'output')


def listup_records(query: str) -> List[CVE_Item]:
    """投げられたクエリを検索し、CVE_Item のリストを返す

    Arguments:
        query {str} -- 検索語句

    Returns:
        List[CVE_Item] -- CVE_Item のリスト
    """
    cve_items = [nvd.get_item(cve_item) for cve_item in search_CVE_records(query)]
    return list(filter(lambda e:e, cve_items))  # None の要素を削除

HEADERS = [
    'CVE_ID', 'Overview', 'CVSS_v3', 'CVSS_v2', 'References', 'Vulnerable_software_versions', 'CWE'
]
def pickup_schema(cve_item: CVE_Item) -> dict:
    """CVE_Itemから表にまとめる項目を抜き出す

    Arguments:
        cve_item {CVE_Item} -- CVE_Item

    Returns:
        dict -- 項目を抜き出した dict
    """
    cvss_v3 = cve_item.impact.get('V3', CVSS_V3({})).baseScore
    cvss_v2 = cve_item.impact.get('V2', CVSS_V2({})).baseScore

    return {
        'CVE_ID': cve_item.id,
        'Overview': cve_item.overview,
        'CVSS_V3': cvss_v3 if cvss_v3 else '',
        'CVSS_V2': cvss_v2 if cvss_v2 else '',
        'References': '\n'.join(cve_item.references),
        'vulnerable_software_versions': '\n'.join(cve_item.vulnerable_software_and_versions),
        'CWE': '\n'.join(cve_item.vulnerability_type),
    }


def to_dataframe(cve_items: List[CVE_Item]) -> pd.DataFrame:
    """CVE_ItemのリストをDFにまとめる

    Arguments:
        cve_items {List[CVE_Item]} -- CVE_Item のリスト

    Returns:
        pd.DataFrame -- Pandas Data frame
    """

    return pd.DataFrame([pickup_schema(e) for e in cve_items])


def create_parser() -> Namespace:
    parser = ArgumentParser(description='nvd のデータを抽出して表にまとめる')

    parser.add_argument('query', nargs='+', help='検索語句（スペース区切りで複数指定可能）')
    parser.add_argument('--out', '-o', help='output file name', default='result')

    return parser.parse_args()


if __name__ == "__main__":
    args = create_parser()

    query: List[str] = args.query
    out: str = args.out
    l: List[CVE_Item] = []
    for q in query:
        print(q, ':')
        l.extend(listup_records(q))
        print('\r', '    done.', ' ' * 100)

    if not l:
        print('[Warning] entries not found')
    else:
        df = to_dataframe(l)
        df.to_csv(pjoin(OUTPUT_DIR, f'{out}.csv'))
        with pd.ExcelWriter(pjoin(OUTPUT_DIR, f'{out}.xlsx'), engine='xlsxwriter') as excel:
            excel.book.add_format({'text_wrap': True})
            df.to_excel(excel)
        print(f'output {len(l)} entries')
