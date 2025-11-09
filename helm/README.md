# Headscale Operator Helm Chart

A Helm chart for deploying the Headscale Operator on Kubernetes. This operator manages [Headscale](https://github.com/juanfont/headscale) instances - an open source, self-hosted implementation of the Tailscale control server.

## Prerequisites

- Kubernetes 1.11.3+
- Helm 3.0+

## Installing the Chart

To install the chart with the release name `headscale-operator`:

```bash
helm install headscale-operator ./helm
```

Or from a repository:

```bash
helm repo add infrado https://charts.infrado.cloud
helm install headscale-operator infrado/headscale-operator
```

## Uninstalling the Chart

To uninstall/delete the `headscale-operator` deployment:

```bash
helm uninstall headscale-operator
```

Note: By default, CRDs are kept even after uninstallation. To remove them:

```bash
kubectl delete crd headscales.headscale.infrado.cloud
```

## Configuration

The following table lists the configurable parameters of the Headscale Operator chart and their default values.

| Parameter | Description | Default |
|-----------|-------------|---------|
| `replicaCount` | Number of operator replicas | `1` |
| `image.repository` | Operator image repository | `controller` |
| `image.tag` | Operator image tag | `latest` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `imagePullSecrets` | Image pull secrets | `[]` |
| `nameOverride` | Override the chart name | `""` |
| `fullnameOverride` | Override the full chart name | `""` |
| `namespaceOverride` | Override the namespace | `""` |
| `serviceAccount.create` | Create service account | `true` |
| `serviceAccount.annotations` | Service account annotations | `{}` |
| `serviceAccount.name` | Service account name | `""` |
| `podAnnotations` | Pod annotations | `{}` |
| `podLabels` | Pod labels | `{}` |
| `podSecurityContext` | Pod security context | See values.yaml |
| `securityContext` | Container security context | See values.yaml |
| `service.type` | Service type | `ClusterIP` |
| `service.port` | Service port | `8443` |
| `resources.limits.cpu` | CPU limit | `500m` |
| `resources.limits.memory` | Memory limit | `128Mi` |
| `resources.requests.cpu` | CPU request | `10m` |
| `resources.requests.memory` | Memory request | `64Mi` |
| `nodeSelector` | Node selector | `{}` |
| `tolerations` | Tolerations | `[]` |
| `affinity` | Affinity rules | `{}` |
| `leaderElection.enabled` | Enable leader election | `true` |
| `metrics.enabled` | Enable metrics endpoint | `true` |
| `metrics.port` | Metrics port | `8443` |
| `rbac.create` | Create RBAC resources | `true` |

### Example Configurations

#### Basic Installation

```bash
helm install headscale-operator ./helm \
  --set image.repository=ghcr.io/infradohq/headscale-operator \
  --set image.tag=v0.1.0
```

#### Custom Resource Limits

```bash
helm install headscale-operator ./helm \
  --set resources.limits.cpu=1000m \
  --set resources.limits.memory=256Mi \
  --set resources.requests.cpu=100m \
  --set resources.requests.memory=128Mi
```

#### Using a Custom Namespace

```bash
helm install headscale-operator ./helm \
  --namespace headscale-system \
  --create-namespace
```

#### With Custom Values File

Create a `custom-values.yaml`:

```yaml
image:
  repository: ghcr.io/infradohq/headscale-operator
  tag: v0.1.0
  pullPolicy: Always

resources:
  limits:
    cpu: 1000m
    memory: 256Mi
  requests:
    cpu: 100m
    memory: 128Mi

nodeSelector:
  kubernetes.io/os: linux
```

Then install:

```bash
helm install headscale-operator ./helm -f custom-values.yaml
```

## Creating a Headscale Instance

After installing the operator, create a Headscale custom resource:

```yaml
apiVersion: headscale.infrado.cloud/v1beta1
kind: Headscale
metadata:
  name: headscale-sample
  namespace: default
spec:
  version: "0.23.0"
  replicas: 1
  config:
    server_url: https://headscale.example.com
    listen_addr: 0.0.0.0:8080
    metrics_listen_addr: 127.0.0.1:9090
    grpc_listen_addr: 127.0.0.1:50443
    
    prefixes:
      v4: 100.64.0.0/10
      v6: fd7a:115c:a1e0::/48
      allocation: sequential
    
    database:
      type: sqlite
      sqlite:
        path: /var/lib/headscale/db.sqlite
        write_ahead_log: true
    
    dns:
      magic_dns: true
      base_domain: example.com
      nameservers:
        global:
          - 1.1.1.1
          - 1.0.0.1
```

Apply it:

```bash
kubectl apply -f headscale-instance.yaml
```

## Monitoring

The operator exposes metrics on port 8443 (by default) which can be scraped by Prometheus. The metrics endpoint is protected by kube-rbac-proxy for authentication and authorization.

## Upgrading

To upgrade the operator:

```bash
helm upgrade headscale-operator ./helm
```

## Support

- GitHub Issues: https://github.com/infradohq/headscale-operator/issues
- Documentation: https://github.com/infradohq/headscale-operator

## License

Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
