package io.github.mdanish98.keycloakmock.impl.handler;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;

import io.vertx.core.http.HttpServerResponse;
import io.vertx.ext.web.RoutingContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class HandlerTestBase {
  @Mock protected RoutingContext routingContext;

  @Mock protected HttpServerResponse serverResponse;

  @Captor protected ArgumentCaptor<String> captor;

  @BeforeEach
  void setupServerResponse() {
    doReturn(serverResponse).when(routingContext).response();
    doReturn(serverResponse).when(serverResponse).putHeader(anyString(), anyString());
  }
}
