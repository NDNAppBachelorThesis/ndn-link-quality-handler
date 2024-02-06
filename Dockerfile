FROM openjdk:20

ENV NDN_HOST="localhost"
ENV NDN_PORT=6363

WORKDIR /adapter
ADD target/ndn-link-quality-handler-1.0-jar-with-dependencies.jar /adapter/ndn-link-quality-handler.jar

CMD ["java", "-jar", "ndn-link-quality-handler.jar"]
