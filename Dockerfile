FROM openjdk:11-jre-slim-buster

ARG PROFILE

ENV USE_PROFILE=$PROFILE
ENV CONFIG_SERVER ""
ENV ENCRYPT_KEY ""

COPY app.jar /app.jar

ENTRYPOINT ["/bin/sh","-c","java -Dspring.profiles.active=${USE_PROFILE} -Duser.timezone=Asia/Seoul -jar ./app.jar"]