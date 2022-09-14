package io.github.mdanish98.keycloakmock.junit5;

import io.github.mdanish98.keycloakmock.junit5.KeycloakMockExtension;
import io.restassured.RestAssured;
import io.restassured.http.ContentType;

import static io.github.mdanish98.keycloakmock.api.ServerConfig.aServerConfig;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class KeycloakMockExtensionJunit5Test {
  private KeycloakMockExtension keyCloakMockExtension;

  @BeforeEach
  void setup() {
    RestAssured.enableLoggingOfRequestAndResponseIfValidationFails();
    RestAssured.port = 8000;
  }

  @AfterEach
  void stopMock() {
    if (keyCloakMockExtension != null) {
      keyCloakMockExtension.afterAll(null);
    }
  }

  @Test
  void mock_is_running() {
    keyCloakMockExtension = new KeycloakMockExtension();
    keyCloakMockExtension.beforeAll(null);

    RestAssured.when()
        .get("/auth/realms/master/protocol/openid-connect/certs")
        .then()
        .statusCode(200)
        .and()
        .contentType(ContentType.JSON);
  }

  @Test
  void https_is_working() {
    keyCloakMockExtension = new KeycloakMockExtension(aServerConfig().withTls(true).build());
    keyCloakMockExtension.beforeAll(null);

    RestAssured.given()
        .relaxedHTTPSValidation()
        .when()
        .get("https://localhost:8000/auth/realms/master/protocol/openid-connect/certs")
        .then()
        .statusCode(200);
  }
}
