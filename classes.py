from typing import List

class CVSS_V3:
    ENUM = {
        'AV': {'N': 'NETWORK', 'A': 'ADJACENT_NETWORK', 'L': 'LOCAL', 'P': 'PHYSICAL'},
        'AC': {'L': 'LOW', 'H': 'HIGH'},
        'PR': {'N': 'NONE', 'L': 'LOW', 'H': 'HIGH'},
        'UI': {'N': 'NONE', 'R': 'REQUIRED'},
        'S': {'U': 'UNCHANGED', 'C': 'CHANGED'},
        'C': {'H': 'HIGH', 'L': 'LOW', 'N': 'NONE'},
        'I': {'H': 'HIGH', 'L': 'LOW', 'N': 'NONE'},
        'A': {'H': 'HIGH', 'L': 'LOW', 'N': 'NONE'}
    }

    def __init__(self, base_metric_v3: dict):
        cvss_v3 = base_metric_v3.get('cvssV3', {})
        self.version: str = cvss_v3.get('version', '')
        self.vectorString: str = cvss_v3.get('vectorString', '')
        self.attackVector: str = cvss_v3.get('attackVector', '')
        self.attackComplexity: str = cvss_v3.get('attackComplexity', '')
        self.privilegesRequired: str = cvss_v3.get('privilegesRequired', '')
        self.userInteraction: str = cvss_v3.get('userInteraction', '')
        self.scope: str = cvss_v3.get('scope', '')
        self.confidentialityImpact: str = cvss_v3.get('confidentialityImpact', '')
        self.integrityimpact: str = cvss_v3.get('integrityimpact', '')
        self.availabilityImpact: str = cvss_v3.get('availabilityImpact', '')
        self.baseScore: float = cvss_v3.get('baseScore', 0.0)
        self.baseSeverity: str = cvss_v3.get('baseSeverity', '')
        self.exploitabilityScore: float = base_metric_v3.get('exploitabilityScore', 0.0)
        self.impactScore: float = base_metric_v3.get('impactScore', 0.0)

    def parse_vector_string(self, vector_string: str):
        pass  # めんどくさくて作ってない


class CVSS_V2:
    def __init__(self, base_metric_v2: dict):
        cvss_v2 = base_metric_v2.get('cvssV3', {})
        self.version: str = cvss_v2.get('version', '')
        self.vectorString: str = cvss_v2.get('vectorString', '')
        self.attackVector: str = cvss_v2.get('attackVector', '')
        self.attackComplexity: str = cvss_v2.get('attackComplexity', '')
        self.authentication: str = cvss_v2.get('authentication', '')
        self.confidentialityImpact: str = cvss_v2.get('confidentialityImpact', '')
        self.integrityimpact: str = cvss_v2.get('integrityimpact', '')
        self.availabilityImpact: str = cvss_v2.get('availabilityImpact', '')
        self.baseScore: float = cvss_v2.get('baseScore', 0.0)
        self.severity: str = base_metric_v2.get('severity', '')
        self.exploitabilityScore: float = base_metric_v2.get('exploitabilityScore', 0.0)
        self.impactScore: float = base_metric_v2.get('impactScore', 0.0)
        self.obtainAllPrivilege: bool = base_metric_v2.get('obtainAllPrivilege', False)
        self.obtainUserPrivilege: bool = base_metric_v2.get('obtainUserPrivilege', False)
        self.obtainOtherPrivilege: bool = base_metric_v2.get('obtainOtherPrivilege', False)
        self.userInteractionRequired: bool = base_metric_v2.get('userInteractionRequired', False)


class CVE_Item:

    @staticmethod
    def __parse_cpe(cpe_match: List[dict]) -> List[str]:
        return_list = []
        for elem in cpe_match:
            if elem['vulnerable']:
                return_list.append(elem['cpe23Uri'])
        return return_list

    def __init__(self, raw_dict: dict):
        self.overview: str = ''
        self.impact: Dict[str, Dict[str, str]] = {}
        self.references: List[str]
        self.vulnerable_software_and_versions: List[str] = []
        self.vulnerability_type: List[str] = []

        cve: dict = raw_dict.get('cve', {})
        impact: dict = raw_dict.get('impact', {})
        references: dict = raw_dict.get('references', {})
        configurations: dict = raw_dict.get('configurations', {})

        if cve:
            self.overview = cve['description']['description_data'][0]['value']
            self.vulnerability_type: List[str] = [e['value'] for e in cve['problemtype']['problemtype_data'][0]['description']]

        if impact:
            self.impact: Dict[str, Dict[str, str]] = {
                'V3': CVSS_V3(impact.get('baseMetricV3', {})),
                'V2': CVSS_V2(impact.get('baseMetricV2', {}))
            }

        if references:
            self.references: List[str] = [data['url'] for data in references.get('references_data', [])]

        if configurations:
            for node in configurations.get('nodes', []):
                if 'children' in node:
                    for c_node in node['children']:
                        self.vulnerable_software_and_versions.extend(self.__parse_cpe(c_node['cpe_match']))
                else:
                    self.vulnerable_software_and_versions.extend(self.__parse_cpe(node['cpe_match']))
