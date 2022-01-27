FROM debian:buster

# install required dependencies
ADD ./tracee-trainer/* /
ADD install-deps.sh /
RUN ./install-deps.sh

ADD ./runner.sh /
RUN chmod +x /runner.sh

ENTRYPOINT ["/runner.sh"]