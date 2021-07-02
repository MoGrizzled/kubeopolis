from kubernetes import client, config

# functions from util or to add to util
import yaml

def read_yaml(file):
  with open(file, 'r') as stream:
    return yaml.load(stream, Loader=yaml.FullLoader)


def write_yaml(data, file):
  """
  Write out a yaml file.
  """

  with open(file, 'w') as outfile:
    yaml.dump(data, outfile, default_flow_style=False)

#cyberark
def get_non_default_name(name):
  if not ((name[:7] == 'system:') or (name == 'edit') or (name == 'admin') or (name == 'cluster-admin') or (name == 'aws-node') or (name[:11] == 'kubernetes-')):
    return name


def check_rule_for_non_resource_ur_ls(rule):
  return rule.non_resource_ur_ls


def process_role(role, accepted):
  if not get_non_default_name(role.metadata.name):
    return False
  if role.metadata.name in accepted:
    return False
  return True


def process_rule(role, rule, resources, verbs):
  if check_rule_for_non_resource_ur_ls(rule):
    print(f'TODO: Check rule {role.metadata.name}')
    return False
  found_attribute = [attribute for attribute in resources if attribute in rule.resources]
  if not (found_attribute):
    return False
  found_actions = [action for action in verbs if action in rule.verbs]
  if not (found_actions):
    return False
  return True


def update_risk_profile_roles(roles, risk_profile, kind):
  for cis_test in risk_profile['cis-tests']['roles']:
    resources = risk_profile['cis-tests']['roles'][cis_test]['resources']
    verbs = risk_profile['cis-tests']['roles'][cis_test]['verbs']
    for role in roles.items:
      if process_role(role, risk_profile['cis-tests']['roles'][cis_test]['accepted']):
        for rule in role.rules:
          if process_rule(role, rule, resources, verbs):
            risk_profile['cis-results'][cis_test][f'{kind}s'].append(role.metadata.name)
  return risk_profile


def update_risk_profile_bindings(role_bindings, risk_profile):
  for cis_test in risk_profile['cis-tests']['roles']:
    for role_binding in role_bindings.items:
      if role_binding.role_ref.name in risk_profile['cis-results'][cis_test][f'{role_binding.role_ref.kind}s'] and get_non_default_name(role_binding.metadata.name):
          risk_profile['cis-results'][cis_test][f'{role_binding.role_ref.kind}Bindings'].update({role_binding.metadata.name:[]})
          for subject in role_binding.subjects:
            if get_non_default_name(subject.name):
              s = {}
              s['kind'] = subject.kind
              s['name'] = subject.name
              s['namespace'] = subject.namespace
              risk_profile['cis-results'][cis_test][f'{role_binding.role_ref.kind}Bindings'][role_binding.metadata.name].append(s)
  return risk_profile


def update_risk_profile_sa_tokens(pods, risk_profile):
  for pod in pods.items:
    for v in pod.spec.volumes:
      if v.projected:
        t = {}
        t['name'] = pod.metadata.name
        t['volume'] = v.name
        risk_profile['cis-results']['5.1.6']['pods'].append(t)
  return risk_profile


def build_risk_profile():
  risk_profile = read_yaml('risk-profile.yaml')
  risk_profile.update(read_yaml('cis-rbac-template.yaml'))
  return risk_profile


def main():
  # Need a work around for the intermediate CA
  # Currently hacking the kubeconfig
  config.load_kube_config()

  # Setup API's
  rbacv1=client.RbacAuthorizationV1Api()
  corev1=client.CoreV1Api()

  # Setup risk profile from template and accepted risks
  print('Building risk profile')
  risk_profile = build_risk_profile()
  print('Evaluating ClusterRoles')
  risk_profile = update_risk_profile_roles(rbacv1.list_cluster_role(watch=False), risk_profile, 'ClusterRole')
  print('Evaluating Roles')
  risk_profile = update_risk_profile_roles(rbacv1.list_role_for_all_namespaces(watch=False), risk_profile, 'Role')
  print('Evaluating ClusterRoleBindings')
  risk_profile = update_risk_profile_bindings(rbacv1.list_cluster_role_binding(watch=False), risk_profile)
  print('Evaluating RoleBindings')
  risk_profile = update_risk_profile_bindings(rbacv1.list_role_binding_for_all_namespaces(watch=False), risk_profile)
  print('Searching pods for Service Account Token Volume Mounts')
  risk_profile = update_risk_profile_sa_tokens(corev1.list_pod_for_all_namespaces(watch=False), risk_profile)

  write_yaml(risk_profile,'risk-report.yaml')

if __name__ == "__main__":
  main()