FROM openjdk:20

ENV FIWARE_HOST="localhost"
ENV FIWARE_PORT=1026
ENV LOG_LEVEL="INFO"

WORKDIR /adapter
ADD target/fiware-ndn-adapter-1.0-jar-with-dependencies.jar /adapter/fiware-ndn-adapter.jar

CMD ["java", "-jar", "fiware-ndn-adapter.jar"]
