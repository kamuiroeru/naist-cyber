from typing import List, Dict
import gzip
from os.path import splitext, dirname, abspath, join as pjoin
from os import chdir
import json
from subprocess import getoutput
from classes import CVE_Item

CVE_LIST_PATH = './src/allitems.csv.gz'

# どこから実行してもOK
chdir(dirname(abspath(__file__)))


def load_gzip_text(filename: str, mode: str = 'rt', **kwargs) -> str:
    """gzip圧縮されたテキストファイルを読み込む

    Arguments:
        filename {str} -- filename
        mode {str} -- mode
    """

    return gzip.open(filename, mode, **kwargs)


def load_json(filename: str) -> dict:
    """JSONファイルを読み込む.gzの場合は展開も同時に実行する

    Arguments:
        filename {str} -- filename

    Returns:
        dict -- jsonをdictに変換したもの
    """

    if splitext(filename)[-1] == '.gz':
        return json.load(load_gzip_text(filename))
    else:
        return json.load(open(filename))


def search_CVE_records(query: str) -> List[str]:
    """queryでCVEを検索する

    Arguments:
        query {str} -- [description]

    Returns:
        List[str] -- [description]
    """
    commands = [
        'gzip', '-dc', CVE_LIST_PATH, '|',
        'grep', query, '|',
        'cut', '-f1', '-d,'
    ]
    return getoutput(' '.join(commands)).split('\n')


class CVE:
    src_path = './src/'
    file_format = 'nvdcve-1.1-{}.json.gz'

    def __init__(self):
        self._cache: Dict[str, List[dict]] = {}

    def _load(self, year: str):
        data = load_json(pjoin(self.src_path, self.file_format.format(year)))
        cve_items = data['CVE_Items']
        self._cache[year] = cve_items

    def _get_cve_year(self, year: str) -> List[dict]:
        if year not in self._cache:
            self._load(year)
        return self._cache[year]

    def get_item(self, cve_id: str) -> dict:
        year = cve_id.split('-')[1]
        cve_items = self._get_cve_year(year)
        searched_items = list(filter(lambda e:e['cve']['CVE_data_meta']['ID'] == cve_id, cve_items))
        if len(searched_items) == 1:
            return CVE_Item(searched_items[0])
        else:
            return CVE_Item({})


if __name__ == "__main__":
    # filename = 'src/allitems.csv.gz'
    filename = 'src/nvdcve-1.1-2016.json.gz'
    d = load_json(filename)
    print(d.keys())
    cve = CVE()
    c = cve.get_item('CVE-2016-9998')
    # for e in search_CVE_records('Thunderbird'):
    #     print(e)
