from kubernetes import client, config

config.load_kube_config()

images = []
v1=client.CoreV1Api()
print("Listing pods with their IPs:")
ret = v1.list_pod_for_all_namespaces(watch=False)
for i in ret.items:
  for container in i.spec.containers:
    if not container.image in images:
      images.append(container.image)

for image in images:
  print(image)