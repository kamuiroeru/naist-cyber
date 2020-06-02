# required jinja2
# vul_top10.tsv の内容を Executive Summary 用に latex document ソースコードに変換する。
# 本文の一部のみが出力されるので \input で使う。

from typing import List
from sys import argv
import pandas as pd

from os.path import abspath, dirname, basename, exists, join as pjoin
from os import getcwd
from sys import path
SCRIPT_PATH = dirname(abspath(__file__))
path.append(pjoin(SCRIPT_PATH, '..'))

from search_attack import CAPEC, extract_ids

from jinja2 import FileSystemLoader, Environment
latex_jinja_env = Environment(
    block_start_string='\BLOCK{',
    block_end_string='}',
    variable_start_string='\VAR{',
    variable_end_string='}',
    comment_start_string='\#{',
    comment_end_string='}',
    line_statement_prefix='%%',
    line_comment_prefix='%#',
    trim_blocks=True,
    autoescape=False,
    loader=FileSystemLoader(SCRIPT_PATH)
)

capec = CAPEC()
LATEX_SUBSUBSECTION_TEMPLATE = latex_jinja_env.get_template('latex_template.tex')

vul_top10_tsv = pd.read_table(pjoin(SCRIPT_PATH, '..', 'output', 'vul_top10.tsv'), index_col=None)

cve_latex_list: List[str] = []
for index, elem in vul_top10_tsv.iterrows():
    cwes: List[str] = elem['CWE'].split('|')
    cwe_ids = []
    capec_ids = []
    for cwe in cwes:
        if len(cwe.split('-')) == 3:
            cwe_id = cwe
        else:
            cwe_id = cwe.split('-')[1]
            capec_ids.extend(extract_ids(capec.get_capec_items_related_cwe(cwe_id)))
    capec_ids = sorted(set(capec_ids), key=lambda x: int(x))
    paste_dict = {
        'CVE': elem['CVE'],
        'description': elem['Description'].replace('\\', '\\textbackslash '),
        'CVSS_V3': elem['CVSS_V3'],
        'CVSS_V2': elem['CVSS_V2'],
        'CWE_IDs': ', '.join(cwe_ids),
        'CAPEC_IDs': ', '.join(capec_ids)
    }
    cve_latex_list.append(
        LATEX_SUBSUBSECTION_TEMPLATE.render(**paste_dict))

with open(pjoin(getcwd(), 'vuls.tex'), 'w') as f:
    f.write('\n\n'.join(cve_latex_list))
