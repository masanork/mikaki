FROM eclipse-temurin:21-jdk AS build
RUN apt-get update && apt-get install -y --no-install-recommends git unzip && rm -rf /var/lib/apt/lists/*
RUN git clone https://github.com/android/keyattestation /opt/keyattestation && git -C /opt/keyattestation checkout --detach 3f550f94a9e3c010dda7cdcad8bca764cd76d4f4
WORKDIR /opt/service
COPY . .
ENV MIKAKI_KEYATTESTATION_CHECKOUT=/opt/keyattestation
RUN /opt/keyattestation/gradlew --no-daemon installDist
FROM eclipse-temurin:21-jre
WORKDIR /opt/service
COPY --from=build /opt/service/build/install/mikaki-android-attestation-verifier ./
USER 10001:10001
ENV BIND_ADDRESS=0.0.0.0 PORT=8080
EXPOSE 8080
ENTRYPOINT ["/opt/service/bin/mikaki-android-attestation-verifier"]
