FROM maven:3.9.11-eclipse-temurin-21 AS build
WORKDIR /workspace
COPY pom.xml .
RUN mvn -B -q dependency:go-offline
COPY src ./src
RUN mvn -B -q -DskipTests package

FROM eclipse-temurin:21-jre
RUN useradd --system --uid 10001 --create-home tte
WORKDIR /app
COPY --from=build /workspace/target/tte-signing-0.1.0-SNAPSHOT.jar /app/app.jar
RUN mkdir -p /app/data/pki && chown -R tte:tte /app
USER tte
EXPOSE 8080
ENTRYPOINT ["java","-jar","/app/app.jar"]
