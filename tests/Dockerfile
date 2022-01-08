FROM debian:buster

ADD ./runner /
ADD ./tracee-trainer/* /
RUN chmod +x /runner

RUN apt-get update

# TRC-3 Code injection
RUN chmod +x ./injector
RUN apt-get install -y ncat gcc

# TRC-4 Dynamic code loading
RUN apt-get install -y upx

# k8s service account tokens
RUN mkdir -p /var/run/secrets/kubernetes.io/serviceaccount
RUN mkdir -p /etc/kubernetes/pki
RUN echo "test" > /var/run/secrets/kubernetes.io/serviceaccount/token
RUN echo "test" > /etc/kubernetes/pki/token
RUN echo "test" > /authorized_keys

ENTRYPOINT ["/runner"]