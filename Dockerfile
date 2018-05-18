FROM maven as builder
COPY . .
RUN mvn clean install -T6 -DskipTests=true -B -Dorg.slf4j.simpleLogger.log.org.apache.maven.cli.transfer.Slf4jMavenTransferListener=warn


FROM openjdk:8-jre-alpine

COPY --from=builder ./scb-engine/target/engine-0.0.1-SNAPSHOT.jar /scb-engine/app.jar
COPY --from=builder ./scb-scanprocesses/nikto-process/target/nikto-process-0.0.1-SNAPSHOT.jar /scb-engine/lib/
COPY --from=builder ./scb-scanprocesses/nmap-process/target/nmap-process-0.0.1-SNAPSHOT.jar /scb-engine/lib/
COPY --from=builder ./scb-scanprocesses/test-process/target/test-process-0.0.1-SNAPSHOT.jar /scb-engine/lib/
COPY --from=builder ./scb-scanprocesses/zap-process/target/zap-process-0.0.1-SNAPSHOT.jar /scb-engine/lib/
COPY --from=builder ./scb-scanprocesses/combined-process/target/combined-process-0.0.1-SNAPSHOT.jar /scb-engine/lib/
COPY --from=builder ./scb-scanprocesses/combined-nmap-nikto-scanprocess/target/combined-nmap-nikto-scanprocess-0.0.1-SNAPSHOT.jar /scb-engine/lib/
COPY --from=builder ./scb-scanprocesses/sslyze-process/target/sslyze-process-0.0.1-SNAPSHOT.jar /scb-engine/lib/
COPY --from=builder ./scb-persistenceproviders/elasticsearch-persistenceprovider/target/elasticsearch-persistenceprovider-0.0.1-SNAPSHOT-jar-with-dependencies.jar /scb-engine/lib/

WORKDIR /scb-engine

EXPOSE 8080

ENTRYPOINT ["java", "-Dloader.path=./lib/,./plugins/", "-jar", "app.jar"]
