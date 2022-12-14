package io.github.mdanish98.keycloakmock.standalone;

import static io.github.mdanish98.keycloakmock.api.ServerConfig.aServerConfig;

import java.util.Collections;
import java.util.List;
import java.util.concurrent.Callable;
import javax.annotation.Nonnull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.github.mdanish98.keycloakmock.api.KeycloakMock;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

@Command(
    description = "Starts a stand-alone keycloak mock.",
    name = "standalone",
    version = "0.13.0",
    mixinStandardHelpOptions = true)
public class Main implements Callable<Void> {
  private static final Logger LOG = LoggerFactory.getLogger(Main.class);

  @SuppressWarnings("FieldMayBeFinal")
  @Option(
      names = {"-p", "--port"},
      description = "The port on which to run (default: ${DEFAULT-VALUE}).")
  private int port = 8000;

  @Option(
      names = {"-s", "--https"},
      description = "Whether to use HTTPS instead of HTTP.")
  private boolean tls;

  @Option(
      names = {"-r", "--mapRolesToResources"},
      description = "If set, roles will be assigned to these resources instead of the realm.",
      paramLabel = "RESOURCE",
      split = ",")
  private final List<String> resourcesToMapRolesTo = Collections.emptyList();

  public static void main(@Nonnull final String[] args) {
    if (System.getProperty("org.slf4j.simpleLogger.logFile") == null) {
      System.setProperty("org.slf4j.simpleLogger.logFile", "System.out");
    }
    int exitCode = new CommandLine(new Main()).execute(args);
    if (exitCode != 0) {
      System.exit(exitCode);
    }
  }

  @Override
  public Void call() {
    new KeycloakMock(
            aServerConfig()
                .withPort(port)
                .withTls(tls)
                .withResourcesToMapRolesTo(resourcesToMapRolesTo)
                .build())
        .start();
    LOG.info("Server is running on {}://localhost:{}", (tls ? "https" : "http"), port);
    return null;
  }
}
