package io.github.mdanish98.keycloakmock.impl.dagger;

import dagger.Component;
import io.github.mdanish98.keycloakmock.impl.TokenGenerator;
import io.jsonwebtoken.SignatureAlgorithm;
import java.security.KeyStore;
import java.security.PublicKey;
import javax.inject.Named;
import javax.inject.Singleton;

@Component(modules = KeyModule.class)
@Singleton
public interface SignatureComponent {
  // Note that while this is currently the same keystore used for storing the signing key-pair,
  // this is just a coincidence. It is provided here only to allow setting up a self-signed TLS
  // endpoint with a separate key-pair.
  KeyStore keyStore();

  PublicKey publicKey();

  @Named("keyId")
  String keyId();

  SignatureAlgorithm signatureAlgorithm();

  TokenGenerator tokenGenerator();
}
