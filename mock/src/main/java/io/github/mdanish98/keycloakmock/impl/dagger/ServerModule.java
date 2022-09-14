package io.github.mdanish98.keycloakmock.impl.dagger;

import dagger.Lazy;
import dagger.Module;
import dagger.Provides;
import io.github.mdanish98.keycloakmock.api.ServerConfig;
import io.github.mdanish98.keycloakmock.impl.UrlConfiguration;
import io.github.mdanish98.keycloakmock.impl.handler.AuthenticationRoute;
import io.github.mdanish98.keycloakmock.impl.handler.CommonHandler;
import io.github.mdanish98.keycloakmock.impl.handler.DelegationRoute;
import io.github.mdanish98.keycloakmock.impl.handler.FailureHandler;
import io.github.mdanish98.keycloakmock.impl.handler.IFrameRoute;
import io.github.mdanish98.keycloakmock.impl.handler.JwksRoute;
import io.github.mdanish98.keycloakmock.impl.handler.LoginRoute;
import io.github.mdanish98.keycloakmock.impl.handler.LogoutRoute;
import io.github.mdanish98.keycloakmock.impl.handler.OptionalBasicAuthHandler;
import io.github.mdanish98.keycloakmock.impl.handler.OutOfBandLoginRoute;
import io.github.mdanish98.keycloakmock.impl.handler.RequestUrlConfigurationHandler;
import io.github.mdanish98.keycloakmock.impl.handler.ResourceFileHandler;
import io.github.mdanish98.keycloakmock.impl.handler.TokenRoute;
import io.github.mdanish98.keycloakmock.impl.handler.WellKnownRoute;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.net.JksOptions;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.common.template.TemplateEngine;
import io.vertx.ext.web.handler.BodyHandler;
import io.vertx.ext.web.handler.ErrorHandler;
import io.vertx.ext.web.templ.freemarker.FreeMarkerTemplateEngine;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.List;
import javax.annotation.Nonnull;
import javax.inject.Named;
import javax.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Module
public class ServerModule {
  private static final Logger LOG = LoggerFactory.getLogger(ServerModule.class);

  @Provides
  @Singleton
  TemplateEngine provideTemplateEngine(@Nonnull Vertx vertx) {
    return FreeMarkerTemplateEngine.create(vertx);
  }

  @Provides
  @Singleton
  @Named("iframe")
  ResourceFileHandler provideIframeHandler() {
    return new ResourceFileHandler("/login-status-iframe.html");
  }

  @Provides
  @Singleton
  @Named("cookie1")
  ResourceFileHandler provideCookie1Handler() {
    return new ResourceFileHandler("/3p-cookies-step1.html");
  }

  @Provides
  @Singleton
  @Named("cookie2")
  ResourceFileHandler provideCookie2Handler() {
    return new ResourceFileHandler("/3p-cookies-step2.html");
  }

  @Provides
  @Singleton
  @Named("keycloakJs")
  ResourceFileHandler provideKeycloakJsHandler() {
    return new ResourceFileHandler("/keycloak.js");
  }

  @Provides
  @Singleton
  @Named("resources")
  List<String> provideResources(@Nonnull ServerConfig serverConfig) {
    return serverConfig.getResourcesToMapRolesTo();
  }

  @Provides
  @Singleton
  Buffer keystoreBuffer(@Nonnull KeyStore keyStore) {
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    try {
      keyStore.store(outputStream, new char[0]);
      return Buffer.buffer(outputStream.toByteArray());
    } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
      throw new IllegalStateException("Unable to prepare keystore for TLS", e);
    }
  }

  @Provides
  @Singleton
  HttpServerOptions provideHttpServerOptions(
      @Nonnull UrlConfiguration defaultConfiguration, @Nonnull Lazy<Buffer> keyStoreBuffer) {
    HttpServerOptions options = new HttpServerOptions().setPort(defaultConfiguration.getPort());
    if (defaultConfiguration.getProtocol().isTls()) {
      options
          .setSsl(true)
          .setKeyStoreOptions(new JksOptions().setValue(keyStoreBuffer.get()).setPassword(""));
    }
    return options;
  }

  @Provides
  @Singleton
  Router provideRouter(
      @Nonnull UrlConfiguration defaultConfiguration,
      @Nonnull Vertx vertx,
      @Nonnull RequestUrlConfigurationHandler requestUrlConfigurationHandler,
      @Nonnull CommonHandler commonHandler,
      @Nonnull FailureHandler failureHandler,
      @Nonnull JwksRoute jwksRoute,
      @Nonnull WellKnownRoute wellKnownRoute,
      @Nonnull LoginRoute loginRoute,
      @Nonnull AuthenticationRoute authenticationRoute,
      @Nonnull OptionalBasicAuthHandler basicAuthHandler,
      @Nonnull TokenRoute tokenRoute,
      @Nonnull IFrameRoute iframeRoute,
      @Nonnull @Named("cookie1") ResourceFileHandler thirdPartyCookies1Route,
      @Nonnull @Named("cookie2") ResourceFileHandler thirdPartyCookies2Route,
      @Nonnull LogoutRoute logoutRoute,
      @Nonnull DelegationRoute delegationRoute,
      @Nonnull OutOfBandLoginRoute outOfBandLoginRoute,
      @Nonnull @Named("keycloakJs") ResourceFileHandler keycloakJsRoute) {
    UrlConfiguration routing = defaultConfiguration.forRequestContext(null, ":realm");
    Router router = Router.router(vertx);
    router
        .route()
        .handler(requestUrlConfigurationHandler)
        .handler(commonHandler)
        .failureHandler(failureHandler)
        .failureHandler(ErrorHandler.create(vertx));
    router.get(routing.getJwksUri().getPath()).handler(jwksRoute);
    router.get(routing.getIssuerPath().resolve(".well-known/*").getPath()).handler(wellKnownRoute);
    router.get(routing.getAuthorizationEndpoint().getPath()).handler(loginRoute);
    router
        .post(routing.getAuthenticationCallbackEndpoint(":sessionId").getPath())
        .handler(BodyHandler.create())
        .handler(authenticationRoute);
    router
        .post(routing.getTokenEndpoint().getPath())
        .handler(BodyHandler.create())
        .handler(basicAuthHandler)
        .handler(tokenRoute);
    router.get(routing.getOpenIdPath("login-status-iframe.html*").getPath()).handler(iframeRoute);
    router
        .get(routing.getOpenIdPath("3p-cookies/step1.html").getPath())
        .handler(thirdPartyCookies1Route);
    router
        .get(routing.getOpenIdPath("3p-cookies/step2.html").getPath())
        .handler(thirdPartyCookies2Route);
    router.get(routing.getEndSessionEndpoint().getPath()).handler(logoutRoute);
    router.get(routing.getOpenIdPath("delegated").getPath()).handler(delegationRoute);
    router.get(routing.getOutOfBandLoginLoginEndpoint().getPath()).handler(outOfBandLoginRoute);
    router.route("/auth/js/keycloak.js").handler(keycloakJsRoute);
    return router;
  }

  @Provides
  @Singleton
  HttpServer provideServer(
      @Nonnull Vertx vertx, @Nonnull HttpServerOptions options, @Nonnull Router router) {
    return vertx
        .createHttpServer(options)
        .requestHandler(router)
        .exceptionHandler(t -> LOG.error("Exception while processing request", t));
  }
}
