# ArgoCD Installation

## Install ArgoCD on cluster
```bash
kubectl create namespace argocd
kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml
```

## Access ArgoCD UI
```bash
kubectl port-forward svc/argocd-server -n argocd 8080:443
```

## Deploy application
```bash
kubectl apply -f argocd/application.yaml
```
