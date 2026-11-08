FROM maven:3.9.9-eclipse-temurin-17 AS build
WORKDIR /build
COPY pom.xml .
COPY src ./src
RUN mvn -B verify

FROM eclipse-temurin:17-jre-alpine
RUN addgroup -S bugparcel && adduser -S bugparcel -G bugparcel
WORKDIR /app
COPY --from=build /build/target/bugparcel-1.4.0.jar app.jar
USER bugparcel
EXPOSE 8087
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=70", "-jar", "app.jar", "--server.address=0.0.0.0"]
