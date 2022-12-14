package io.github.mdanish98.keycloakmock.junit;

import io.github.mdanish98.keycloakmock.junit.KeycloakMockRule;
import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

public class KeycloakMockRuleJunit4Test {

  @Rule public KeycloakMockRule keycloakMockRule = new KeycloakMockRule();

  @Before
  public void setup() {
    RestAssured.enableLoggingOfRequestAndResponseIfValidationFails();
    RestAssured.port = 8000;
  }

  @Test
  public void mock_is_running() {
    RestAssured.when()
        .get("/auth/realms/master/protocol/openid-connect/certs")
        .then()
        .statusCode(200)
        .and()
        .contentType(ContentType.JSON);
  }
}
