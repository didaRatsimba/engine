FROM maven as builder
COPY . .
RUN mvn clean install -T6 -DskipTests=true -B -Dorg.slf4j.simpleLogger.log.org.apache.maven.cli.transfer.Slf4jMavenTransferListener=warn


FROM openjdk:8-jre-alpine

ARG COMMIT_ID=unkown
ARG REPOSITORY_URL=unkown
ARG BRANCH=unkown
ARG BUILD_DATE
ARG VERSION

COPY --from=builder ./scb-engine/target/engine-0.0.1-SNAPSHOT.jar /scb-engine/app.jar
COPY --from=builder ./scb-scanprocesses/nikto-process/target/nikto-process-0.0.1-SNAPSHOT.jar /scb-engine/lib/
COPY --from=builder ./scb-scanprocesses/nmap-process/target/nmap-process-0.0.1-SNAPSHOT.jar /scb-engine/lib/
COPY --from=builder ./scb-scanprocesses/test-process/target/test-process-0.0.1-SNAPSHOT.jar /scb-engine/lib/
COPY --from=builder ./scb-scanprocesses/zap-process/target/zap-process-0.0.1-SNAPSHOT.jar /scb-engine/lib/
COPY --from=builder ./scb-scanprocesses/combined-nmap-nikto-scanprocess/target/combined-nmap-nikto-scanprocess-0.0.1-SNAPSHOT.jar /scb-engine/lib/
COPY --from=builder ./scb-scanprocesses/sslyze-process/target/sslyze-process-0.0.1-SNAPSHOT.jar /scb-engine/lib/
COPY --from=builder ./scb-scanprocesses/arachni-process/target/arachni-process-1.0-SNAPSHOT.jar /scb-engine/lib/
COPY --from=builder ./scb-scanprocesses/subdomain-scanner-process/target/subdomain-scanner-process-1.0-SNAPSHOT.jar /scb-engine/lib/

COPY --from=builder ./scb-persistenceproviders/elasticsearch-persistenceprovider/target/elasticsearch-persistenceprovider-0.0.1-SNAPSHOT-jar-with-dependencies.jar /scb-engine/lib/

WORKDIR /scb-engine

EXPOSE 8080

LABEL org.opencontainers.image.title="secureCodeBox Engine" \
    org.opencontainers.image.description="Orchestrating various security scans." \
    org.opencontainers.image.authors="iteratec GmbH" \
    org.opencontainers.image.vendor="iteratec GmbH" \
    org.opencontainers.image.documentation="https://github.com/secureCodeBox/secureCodeBox" \
    org.opencontainers.image.licenses="Apache-2.0" \
    org.opencontainers.image.version=$VERSION \
    org.opencontainers.image.url=$REPOSITORY_URL \
    org.opencontainers.image.source=$REPOSITORY_URL \
    org.opencontainers.image.revision=$COMMIT_ID \
    org.opencontainers.image.created=$BUILD_DATE

ENTRYPOINT ["java", "-Dloader.path=./lib/,./plugins/", "-jar", "app.jar"]
