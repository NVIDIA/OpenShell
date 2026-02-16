#!/bin/sh
set -eu

export KUBECONFIG=/etc/rancher/k3s/k3s.yaml

kubectl get --raw='/readyz' >/dev/null 2>&1 || exit 1

kubectl -n navigator get statefulset/navigator >/dev/null 2>&1 || exit 1
kubectl -n navigator wait --for=jsonpath='{.status.readyReplicas}'=1 statefulset/navigator --timeout=1s >/dev/null 2>&1 || exit 1

kubectl -n navigator get gateway/navigator-gateway >/dev/null 2>&1 || exit 1
kubectl -n navigator wait --for=condition=Programmed gateway/navigator-gateway --timeout=1s >/dev/null 2>&1 || exit 1

TLS_ENABLED="${NAV_GATEWAY_TLS_ENABLED:-}"
if [ -z "$TLS_ENABLED" ]; then
  for values_file in \
    /var/lib/rancher/k3s/server/manifests/navigator-helmchart.yaml \
    /opt/navigator/manifests/navigator-helmchart.yaml
  do
    if [ -f "$values_file" ]; then
      TLS_ENABLED=$(awk '
        $1=="valuesContent:" { in_values=1; next }
        !in_values { next }
        $1=="gateway:" { in_gateway=1; next }
        in_gateway && $1=="tls:" { in_tls=1; next }
        in_gateway && in_tls && $1=="enabled:" { print $2; exit }
      ' "$values_file")
      if [ -n "$TLS_ENABLED" ]; then
        break
      fi
    fi
  done
fi

case "${TLS_ENABLED:-}" in
  true|TRUE|True|1|yes|YES) TLS_ENABLED=true ;;
  false|FALSE|False|0|no|NO|"") TLS_ENABLED=false ;;
  *) TLS_ENABLED=false ;;
esac

if [ "$TLS_ENABLED" = "true" ]; then
  bundle=$(kubectl -n navigator get secret navigator-cli-client -o jsonpath='{.data.ca\.crt}{.data.tls\.crt}{.data.tls\.key}' 2>/dev/null || true)
  [ -n "$bundle" ] || exit 1
fi
