from typing import List, Dict, Union, DefaultDict
from uuid import uuid4
from io import BytesIO
import requests
import xml.etree.ElementTree as ET
from zipfile import ZipFile
from tqdm import tqdm
from collections import defaultdict
from argparse import ArgumentParser, Namespace

from os.path import abspath, dirname, basename, exists, join as pjoin
from sys import path
SCRIPT_PATH = dirname(abspath(__file__))
path.append(SCRIPT_PATH)

from scripts.custom_io import dump_pickle_gzip, load_pickle_gzip
from scripts.classes import CAPEC_Item

CAPEC_XML_URLS = [
    'https://capec.mitre.org/data/xml/views/1000.xml.zip',
    'https://capec.mitre.org/data/xml/views/3000.xml.zip'
]


def download_xml_zip(url: str) -> ET.Element:
    """ *.xml.zip をダウンロードして、解凍、xml を parse、結果の Element Object を返す"""
    r = requests.get(url)
    my_zip = ZipFile(BytesIO(r.content))
    inside_zip = my_zip.namelist()[0]
    return ET.fromstring(my_zip.open(inside_zip).read())


class CAPEC:
    """CAPEC のデータを処理するクラス
    """
    __CAPEC_XML_URLS = [
        'https://capec.mitre.org/data/xml/views/1000.xml.zip',
        'https://capec.mitre.org/data/xml/views/3000.xml.zip'
    ]
    __dumpfile_path = pjoin(SCRIPT_PATH, 'scripts', 'src', 'capec.pkl.gz')

    def update_cache(self) -> Dict[str, CAPEC_Item]:
        """CAPEC キャッシュをアップデートする"""
        capec_detail: Dict[str, dict] = {}
        for url in tqdm(self.__CAPEC_XML_URLS):
            root = download_xml_zip(url)
            attack_patterns = root[0]
            for attack_pattern in attack_patterns:
                attack_id: str = attack_pattern.get('ID')
                attack_name: str = attack_pattern.get('Name')
                related_weeknesses_element = attack_pattern.find('{http://capec.mitre.org/capec-3}Related_Weaknesses')
                if related_weeknesses_element:
                    related_weaknesses: List[str] = [rw.get('CWE_ID') for rw in related_weeknesses_element]
                else:
                    related_weaknesses: List[str] = []
                capec_detail[attack_id] = CAPEC_Item({
                    'id': attack_id,
                    'name': attack_name,
                    'related_weaknesses': related_weaknesses
                })

        dump_pickle_gzip(capec_detail, self.__dumpfile_path)
        return capec_detail

    def __init__(self, update: bool=False):
        if update:
            print('Updating CAPEC Data')
            self.capec = self.update_cache()
        else:
            if exists(self.__dumpfile_path):
                print('Loading CAPEC Data')
                self.capec = load_pickle_gzip(self.__dumpfile_path)
            else:
                print('[Warning] CAPEC cache file is not found')
                self.capec = {}

        # CWE_ID に紐づく CAPEC_Item を検索するための辞書を作成
        self.cwe_to_capecs: DefaultDict[str, List[CAPEC_Item]] = defaultdict(list)
        for capec_id, capec_item in self.capec.items():
            for cwe in capec_item.related_weaknesses:
                self.cwe_to_capecs[cwe].append(capec_item)

    def get_capec_item(self, capec_id: str) -> Union[CAPEC_Item, None]:
        """CAPEC_ID を受けて CAPEC_Item を返す"""
        return self.capec.get(capec_id)

    def get_capec_items_related_cwe(self, cwe_id: str) -> List[CAPEC_Item]:
        """CWE_ID を受けて CAPEC_Item のリストを返す"""
        return self.cwe_to_capecs.get(cwe_id, [])


def create_parser() -> Namespace:
    parser = ArgumentParser(description='CAPEC と CWE の関係を調べる')

    parser.add_argument('--update', '-u', action='store_true', help='処理前に NVD データキャッシュファイルをアップデートする')

    return parser.parse_args()


def sort_capecs(capecs: List[CAPEC_Item]) -> List[CAPEC_Item]:
    return sorted(capecs, key=lambda capec: int(capec.id))


def extract_ids(capecs: List[CAPEC_Item]) -> List[str]:
    return list(map(lambda capec: capec.id, sort_capecs(capecs)))


if __name__ == "__main__":
    args = create_parser()
    update: bool = args.update
    capec = CAPEC(update)
