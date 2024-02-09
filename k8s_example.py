import logging

import requests
from yaml import dump



class V1Connector:
    def __init__(self, api_key: str, api_version: str = 'beta') -> None:
        self.api_key = api_key
        self.base_url = f'https://api.xdr.trendmicro.com/{api_version}/containerSecurity'
        self.headers = {'Authorization': f'Bearer {self.api_key}'}

    def list_clusters(self) -> dict | None:
        try:
            response = requests.get(
                f'{self.base_url}/kubernetesClusters',
                headers=self.headers
            )

            if response.status_code == 200:
                return response.json()
            return {'error': response.reason, 'status_code': response.status_code}
        except Exception as error:
            logging.error(f'Error in list_clusters: {error}')


    def list_policies(self) -> dict | None:
        try:
            response = requests.get(
                f'{self.base_url}/policies',
                headers=self.headers
            )

            if response.status_code == 200:
                return response.json()
            return {'error': response.reason, 'status_code': response.status_code}
        except Exception as error:
            logging.error(f'Error in list_policies: {error}')

    def list_rulesets(self) -> dict | None:
        try:
            response = requests.get(
                f'{self.base_url}/rulesets',
                headers=self.headers
            )

            if response.status_code == 200:
                return response.json()
            return {'error': response.reason, 'status_code': response.status_code}
        except Exception as error:
            logging.error(f'Error in list_rulesets: {error}')

    def list_vulns(self) -> dict | None:
        try:
            response = requests.get(
                f'{self.base_url}/vulnerabilities',
                headers=self.headers
            )

            if response.status_code == 200:
                return response.json()
            return {'error': response.reason, 'status_code': response.status_code}
        except Exception as error:
            logging.error(f'Error in list_vulns: {error}')

    def register_cluster(self, name: str, description: str = "",
                         policy_id: str = "", arn: str = "",
                         exclusions: list = [],
                         runtime: bool = True, vuln_scanning: bool = True,
                         inventory: bool = True) -> dict | str | None:
        try:
            response = requests.post(
                f'{self.base_url}/kubernetesClusters',
                headers=self.headers,
                json={
                    'name': name,
                    'description': description,
                    'policyId': policy_id,
                    'arn': arn
                }
            )

            if response.status_code == 201:
                data = response.json()
                yaml_dict = {
                    'cloudOne' : {
                        'apiKey': data.get('apiKey'),
                        'endpoint': data.get('endpointUrl'),
                        'exclusion': {
                            'namespaces': exclusions
                        },
                        'runtimeSecurity': {
                            'enabled': runtime
                        },
                        'vulnerabilityScanning': {
                            'enabled': vuln_scanning
                        },
                        'inventoryCollection': {
                            'enabled': inventory
                        }
                    }
                }

                return dump(yaml_dict)
            return {'error': response.reason, 'status_code': response.status_code}
        except Exception as error:
            logging.error(f'Error in register_cluster: {error}')
