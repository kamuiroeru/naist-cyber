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
    __filename_template = 'nvdcve-1.1-{}.json.gz'
    __url_template = 'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{}.json.gz'
    __json_encode = 'utf-8'
    __start_year = 2002
    __end_year: int = datetime.now().year

    def nvd_json_data_downloader(self):
        """NVD の Data Feeds（2002 ~ 実行年までのすべて） をダウンロードして NVD.pkl.gz に dump する"""

        nvd_data_dict: Dict[str, CVE_Item] = {}
        print('Downloading NVD Data Feeds')
        for year in tqdm(range(self.__start_year, self.__end_year + 1)):
            response = requests.get(self.__url_template.format(year), stream=True)
            data = json.loads(gzip.decompress(response.content).decode(self.__json_encode))
            for cve in data['CVE_Items']:
                cve_id = cve['cve']['CVE_data_meta']['ID']
                nvd_data_dict[cve_id] = CVE_Item(cve)

        print('Dumping NVD Data')
        dump_pickle_gzip(nvd_data_dict, self.__dumpfile_path)


    def _load(self) -> Dict[str, CVE_Item]:
        if not exists(self.__dumpfile_path):
            self.nvd_json_data_downloader()
        print('Loading NVD Data')
        return load_pickle_gzip(self.__dumpfile_path)

    def __init__(self):
        self.nvd = self._load()

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
