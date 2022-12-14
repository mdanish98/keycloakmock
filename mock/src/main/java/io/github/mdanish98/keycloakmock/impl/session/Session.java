package io.github.mdanish98.keycloakmock.impl.session;

import java.util.List;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public interface Session {
  @Nonnull
  String getClientId();

  @Nonnull
  String getSessionId();

  @Nonnull
  String getUsername();

  @Nonnull
  List<String> getRoles();

  @Nullable
  String getNonce();
}
