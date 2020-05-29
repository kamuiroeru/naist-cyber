import pickle
import gzip
import json
from os.path import splitext


def dump_pickle_gzip(obj: object, filepath: str):
    """Python オブジェクト を gzip 圧縮した pickle にする

    Arguments:
        obj {object} -- 保存する Python オブジェクト
        filepath {str} -- 保存先
    """

    if filepath[-7:] != '.pkl.gz':
        filepath += '.pkl.gz'

    with gzip.open(filepath, 'wb') as gf:
        pickle.dump(obj, gf)


def load_pickle_gzip(filepath: str) -> object:
    """gzip 圧縮した pickle を読み出す

    Arguments:
        filepath {str} -- 読み出す pkl.gz
    """

    with gzip.open(filepath, 'rb') as gf:
        return pickle.load(gf)


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
