from typing import List, Dict, Union
import gzip
from os.path import dirname, abspath, exists, join as pjoin
from os import chdir
import json
from datetime import datetime
import requests
from tqdm import tqdm
import pandas as pd

# どこから実行してもOK
SCRIPT_PATH = dirname(abspath(__file__))
from sys import path
path.append(SCRIPT_PATH)

from .classes import CVE_Item
from .custom_io import dump_pickle_gzip, load_pickle_gzip


def search_CVE_records(query: str) -> List[str]:
    """queryでCVEを検索する

    Arguments:
        query {str} -- [description]

    Returns:
        List[str] -- [description]
    """
    __url_template = 'https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={}'

    query_string = '+'.join(query.strip().split())
    dfs: List[pd.DataFrame] = pd.read_html(__url_template.format(query_string))
    search_result_df = dfs[2]
    cve_list = search_result_df['Name'].tolist()

    return cve_list


class NVD:
    __dumpfile_path = pjoin(SCRIPT_PATH, 'src', 'nvd.pkl.gz')
    __metafile_path = pjoin(SCRIPT_PATH, 'src', 'meta.pkl.gz')
    __filename_template = 'nvdcve-1.1-{}.json.gz'
    __meta_url_template = 'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{}.meta'
    __url_template = 'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{}.json.gz'
    __json_encode = 'utf-8'
    __year_list = list(map(str, range(2002, datetime.now().year + 1))) + ['Recent', 'Modified']

    def _download_json_data(self, year: str) -> Dict[str, CVE_Item]:
        """指定された json.gz ファイルをダウンロードしてくる"""
        nvd_data_dict: Dict[str, CVE_Item] = {}
        response = requests.get(self.__url_template.format(year), stream=True)
        data = json.loads(gzip.decompress(response.content).decode(self.__json_encode))
        for cve in data['CVE_Items']:
            cve_id = cve['cve']['CVE_data_meta']['ID']
            nvd_data_dict[cve_id] = CVE_Item(cve)
        return nvd_data_dict

    def update_nvd_cache(self) -> Dict[str, CVE_Item]:
        """NVD のキャッシュをアップデートする。
        metaデータを確認してネット上のファイルが更新されていたら再度ダウンロードする。
        """

        # ダンプデータの読み込み or 初期化
        if exists(self.__dumpfile_path):
            nvd_data_dict: Dict[str, CVE_Item] = load_pickle_gzip(self.__dumpfile_path)
        else:
            nvd_data_dict: Dict[str, CVE_Item] = {}

        # 更新日時データの読み込み or 初期化
        if exists(self.__metafile_path):
            update_date: Dict[str, str] = load_pickle_gzip(self.__metafile_path)
        else:
            update_date: Dict[str, str] = {}

        for year in tqdm(self.__year_list):
            # 更新日時を確認
            response = requests.get(self.__meta_url_template.format(year))
            last_modified_date = response.text.split()[0][17:]

            # 初回ダウンロード or 更新されていたら
            if year not in update_date or last_modified_date != update_date[year]:
                update_date[year] = last_modified_date
                nvd_data_dict.update(self._download_json_data(year))

        dump_pickle_gzip(nvd_data_dict, self.__dumpfile_path)
        dump_pickle_gzip(update_date, self.__metafile_path)

        return nvd_data_dict

    def __init__(self, update: bool=False):
        if update:
            print('Updating NVD Data')
            self.nvd = self.update_nvd_cache()
        else:
            if exists(self.__dumpfile_path):
                print('Loading NVD Data')
                self.nvd = load_pickle_gzip(self.__dumpfile_path)
            else:
                print('[Warning] NVD cache file is not found')
                self.nvd = {}

    def get_item(self, cve_id: str) -> Union[CVE_Item, None]:
        cve_item = self.nvd.get(cve_id, None)
        if cve_item is not None:
            return cve_item
        else:
            return None


if __name__ == "__main__":
    sns = ['YouTube', 'Facebook', 'WhatsApp', 'Instagram', 'Twitter']
    cloud_platforms = ['AWS', 'Azure']

    print('searching SNS CVE')
    sns_cve = []
    for query in sns:
        print('\r', query, ' ' * 100, end='')
        sns_cve.extend(search_CVE_records(query))
    print()

    print('searching cloud platforms CVE')
    cloud_platforms_cve = []
    for query in cloud_platforms:
        print('\r', query, ' ' * 100, end='')
        cloud_platforms_cve.extend(search_CVE_records(query))
    print()
