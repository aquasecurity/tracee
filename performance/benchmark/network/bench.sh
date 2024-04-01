#!/bin/bash -x

CleanUp() {
    kubectl delete -f manifests/policies/bench.yaml -f manifests/loadgenerator.yaml -f manifests/microservices.yaml -f manifests/tracee.yaml
    exit 1
}

# constants

TRACEE_IMAGE=${1:-"docker.io/aquasec/tracee:0.20.0"}
BENCH_TIME=${2:-900}
RESULT_ID=${3:-"default"}
BENCHMARK_NAME="tracee_network_benchmark"


# add cleanup procedure

trap CleanUp SIGINT SIGTERM SIGTSTP ERR

# setup benchmark

benchmark_node=$(kubectl get nodes -l type=bench,benchmark-test=boutique-msvc | awk '{print $1}' | tail -n 1)
base_node=$(kubectl get nodes -l type=base,benchmark-test=boutique-msvc | awk '{print $1}' | tail -n 1)

kubectl apply -f manifests/policies/bench.yaml -f manifests/microservices.yaml -f manifests/tracee.yaml
kubectl patch daemonset tracee -p '{"spec":{"template":{"spec":{"containers":[{"name":"tracee","image":'\"$TRACEE_IMAGE\"'}]}}}}'

daemonsets=("adservice" "cartservice" "checkoutservice" "currencyservice" "emailservice" "frontend" "paymentservice" "productcatalogservice" "recommendationservice" "redis-cart" "shippingservice" "tracee")

# stabilize...

#sleep 30
for ds in ${daemonsets[@]}; do
    kubectl rollout status daemonset $ds &
done
wait

# start loadgenerator

kubectl apply -f manifests/loadgenerator.yaml

# stabilize again...
kubectl rollout status daemonset loadgenerator

# find loadgenerators

benchmark_lg=$(kubectl get pods -l app=loadgenerator -o wide | grep $benchmark_node | awk '{print $1}')
base_lg=$(kubectl get pods -l app=loadgenerator -o wide | grep $base_node | awk '{print $1}')

# run benchmark

sleep $BENCH_TIME

# calculate benchmark result

bench_avg_latency=$(kubectl logs $benchmark_lg --tail=2 | head -n 1 | awk '{print $5}')
base_avg_latency=$(kubectl logs $base_lg --tail=2 | head -n 1 | awk '{print $5}')

overhead=$(echo "scale=8 ; (($bench_avg_latency / $base_avg_latency)*100)-100" | bc)
printf '%s = %f%%\n' "overhead" $overhead

# create json output
jq -n '{name: $bench_name, value: $bench_v, unit: "%"}' \
    --arg bench_name $BENCHMARK_NAME \
    --arg bench_v $overhead > bench_output.json

# call cleanup manually

CleanUp
