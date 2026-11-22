# syntax=docker/dockerfile:1.7
# One image recipe for both JVM services: docker build --build-arg APP=pep-gateway|control-plane -f deploy/docker/java.Dockerfile .
ARG APP

FROM eclipse-temurin:21.0.8_9-jdk-noble AS build
ARG APP
WORKDIR /src
COPY gradlew settings.gradle.kts build.gradle.kts gradle.properties ./
COPY gradle ./gradle
RUN --mount=type=cache,target=/root/.gradle,sharing=locked ./gradlew --no-daemon --version >/dev/null
COPY packages ./packages
COPY apps/pep-gateway ./apps/pep-gateway
COPY apps/control-plane ./apps/control-plane
COPY policies ./policies
RUN --mount=type=cache,target=/root/.gradle,sharing=locked ./gradlew --no-daemon -q ":${APP}:bootJar" -x test \
 && cp "apps/${APP}/build/libs/${APP}.jar" /app.jar

FROM eclipse-temurin:21.0.8_9-jre-noble
ARG APP
ENV APP=${APP} \
    JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=75 -XX:+ExitOnOutOfMemoryError -XX:+UseZGC -Dfile.encoding=UTF-8"
RUN groupadd --system --gid 10001 warrant && useradd --system --uid 10001 --gid warrant --no-create-home warrant \
 && mkdir -p /var/lib/warrant/keys && chown -R warrant:warrant /var/lib/warrant && chmod 700 /var/lib/warrant/keys
COPY --from=build --chown=root:root /app.jar /opt/warrant/app.jar
USER 10001:10001
WORKDIR /opt/warrant
EXPOSE 8080 8081
ENTRYPOINT ["java", "-jar", "/opt/warrant/app.jar"]
