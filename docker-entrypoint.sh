#!/bin/sh
# LOCAL_FORWARD="8180:host.docker.internal:8180" — проброс 127.0.0.1:8180 внутри контейнера на Keycloak хоста.
# Приложение обращается к Keycloak по http://localhost:8180, как и браузер, поэтому issuer токенов
# (http://localhost:8180/realms/GovApps) одинаковый у всех участников token exchange.
if [ -n "$LOCAL_FORWARD" ]; then
  port="${LOCAL_FORWARD%%:*}"
  target="${LOCAL_FORWARD#*:}"
  socat "TCP-LISTEN:${port},bind=127.0.0.1,fork,reuseaddr" "TCP:${target}" &
fi
exec java $JAVA_OPTS -jar /app/app.jar "$@"
