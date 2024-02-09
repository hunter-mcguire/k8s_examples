# k8s_example

### Install python packages
pip install -r requirement.txt


```python
from k8s_example import V1Connector

# Set api key and instantiate connector
v1_api_key = '<api_key>'
connector = V1Connector(v1_api_key)

# List clusters, policies, rulsets, and vulnerabilities
clusters = connector.list_clusters()
policies = connector.list_policies()
rulesets = connector.list_rulesets()
vulns = connector.list_vulns()

# Register a new cluster. 
new_cluster = connector.register_cluster(
    name='new_dev_cluster',
    description="For test env",
    policy_id='DevPolicy-2amiWtdyz19o32uYIuMtuTQBzDu',
    exclusions=['kube-system'],
    runtime=True,
    vuln_scanning=True,
    inventory=True
)

# Create overrides.yaml for helm deployment
if new_cluster:
    with open('overrides.yaml') as file:
        file.write(new_cluster)
```