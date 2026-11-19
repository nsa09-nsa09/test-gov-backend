#!/bin/sh
# LOCAL_FORWARD="18630:host.docker.internal:18630" — проброс 127.0.0.1:18630 внутри контейнера на Keycloak хоста.
# Приложение обращается к Keycloak по http://localhost:18630, как и браузер, поэтому issuer токенов
# (http://localhost:18630/realms/GovApps) одинаковый у всех участников token exchange.
if [ -n "$LOCAL_FORWARD" ]; then
  port="${LOCAL_FORWARD%%:*}"
  target="${LOCAL_FORWARD#*:}"
  socat "TCP-LISTEN:${port},bind=127.0.0.1,fork,reuseaddr" "TCP:${target}" &
fi
exec java $JAVA_OPTS -jar /app/app.jar "$@"
