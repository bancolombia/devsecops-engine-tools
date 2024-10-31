FROM #{eclipse-temurin_17_alpine-digest}#
EXPOSE 22
LABEL version="#{Build.BuildNumber}#" maintainer="Proyecto Backend DevSecOps Engine" description="Microservicio para descarga y carga de reportes de prisma cloud"
COPY ms_extractor.jar ms_extractor.jar
COPY docker/check.sh check.sh
RUN mkdir -p /tmp/parquet/schema
RUN echo "#{FINDING_SCHEMA}#" > /tmp/parquet/schema/finding.schema
RUN chmod +x check.sh
RUN apk update && apk add --no-cache libc6-compat
ENV JAVA_OPTS="-XX:+UseContainerSupport -Djava.security.egd=file:/dev/./urandom"
USER #{eclipse-temurin_17_alpine-user}#
ENTRYPOINT [ "sh", "-c", "java $JAVA_OPTS  -jar ms_extractor.jar" ]
