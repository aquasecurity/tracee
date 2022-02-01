FROM debian:buster

ADD ./* /

RUN ./install-deps.sh

RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]