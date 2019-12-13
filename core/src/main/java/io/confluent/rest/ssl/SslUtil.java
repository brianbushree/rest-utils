/**
 * Copyright 2019 Confluent Inc.
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.confluent.rest.ssl;

import io.confluent.rest.RestConfig;

import org.apache.kafka.common.config.ConfigException;
import org.eclipse.jetty.util.ssl.SslContextFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

public class SslUtil {

  private static final Logger log = LoggerFactory.getLogger(SslUtil.class);

  @SuppressWarnings("deprecation")
  private static void configureClientAuth(SslContextFactory sslContextFactory, RestConfig config) {
    String clientAuthentication = config.getString(RestConfig.SSL_CLIENT_AUTHENTICATION_CONFIG);

    if (config.originals().containsKey(RestConfig.SSL_CLIENT_AUTH_CONFIG)) {
      if (config.originals().containsKey(RestConfig.SSL_CLIENT_AUTHENTICATION_CONFIG)) {
        log.warn(
            "The {} configuration is deprecated. Since a value has been supplied for the {} "
                + "configuration, that will be used instead",
            RestConfig.SSL_CLIENT_AUTH_CONFIG,
            RestConfig.SSL_CLIENT_AUTHENTICATION_CONFIG
        );
      } else {
        log.warn(
            "The configuration {} is deprecated and should be replaced with {}",
            RestConfig.SSL_CLIENT_AUTH_CONFIG,
            RestConfig.SSL_CLIENT_AUTHENTICATION_CONFIG
        );
        clientAuthentication = config.getBoolean(RestConfig.SSL_CLIENT_AUTH_CONFIG)
            ? RestConfig.SSL_CLIENT_AUTHENTICATION_REQUIRED
            : RestConfig.SSL_CLIENT_AUTHENTICATION_NONE;
      }
    }

    switch (clientAuthentication) {
      case RestConfig.SSL_CLIENT_AUTHENTICATION_REQUIRED:
        sslContextFactory.setNeedClientAuth(true);
        break;
      case RestConfig.SSL_CLIENT_AUTHENTICATION_REQUESTED:
        sslContextFactory.setWantClientAuth(true);
        break;
      case RestConfig.SSL_CLIENT_AUTHENTICATION_NONE:
        break;
      default:
        throw new ConfigException(
            "Unexpected value for {} configuration: {}",
            RestConfig.SSL_CLIENT_AUTHENTICATION_CONFIG,
            clientAuthentication
        );
    }
  }

  public static SslContextFactory createSslContextFactory(RestConfig config) {
    SslContextFactory sslContextFactory = new SslContextFactory.Server();
    if (!config.getString(RestConfig.SSL_KEYSTORE_LOCATION_CONFIG).isEmpty()) {
      sslContextFactory.setKeyStorePath(
          config.getString(RestConfig.SSL_KEYSTORE_LOCATION_CONFIG)
      );
      sslContextFactory.setKeyStorePassword(
          config.getPassword(RestConfig.SSL_KEYSTORE_PASSWORD_CONFIG).value()
      );
      sslContextFactory.setKeyManagerPassword(
          config.getPassword(RestConfig.SSL_KEY_PASSWORD_CONFIG).value()
      );
      sslContextFactory.setKeyStoreType(
          config.getString(RestConfig.SSL_KEYSTORE_TYPE_CONFIG)
      );

      if (!config.getString(RestConfig.SSL_KEYMANAGER_ALGORITHM_CONFIG).isEmpty()) {
        sslContextFactory.setKeyManagerFactoryAlgorithm(
            config.getString(RestConfig.SSL_KEYMANAGER_ALGORITHM_CONFIG));
      }
    }

    configureClientAuth(sslContextFactory, config);

    List<String> enabledProtocols = config.getList(RestConfig.SSL_ENABLED_PROTOCOLS_CONFIG);
    if (!enabledProtocols.isEmpty()) {
      sslContextFactory.setIncludeProtocols(enabledProtocols.toArray(new String[0]));
    }

    List<String> cipherSuites = config.getList(RestConfig.SSL_CIPHER_SUITES_CONFIG);
    if (!cipherSuites.isEmpty()) {
      sslContextFactory.setIncludeCipherSuites(cipherSuites.toArray(new String[0]));
    }

    sslContextFactory.setEndpointIdentificationAlgorithm(
        config.getString(RestConfig.SSL_ENDPOINT_IDENTIFICATION_ALGORITHM_CONFIG));

    if (!config.getString(RestConfig.SSL_TRUSTSTORE_LOCATION_CONFIG).isEmpty()) {
      sslContextFactory.setTrustStorePath(
          config.getString(RestConfig.SSL_TRUSTSTORE_LOCATION_CONFIG)
      );
      sslContextFactory.setTrustStorePassword(
          config.getPassword(RestConfig.SSL_TRUSTSTORE_PASSWORD_CONFIG).value()
      );
      sslContextFactory.setTrustStoreType(
          config.getString(RestConfig.SSL_TRUSTSTORE_TYPE_CONFIG)
      );

      if (!config.getString(RestConfig.SSL_TRUSTMANAGER_ALGORITHM_CONFIG).isEmpty()) {
        sslContextFactory.setTrustManagerFactoryAlgorithm(
            config.getString(RestConfig.SSL_TRUSTMANAGER_ALGORITHM_CONFIG)
        );
      }
    }

    sslContextFactory.setProtocol(config.getString(RestConfig.SSL_PROTOCOL_CONFIG));
    if (!config.getString(RestConfig.SSL_PROVIDER_CONFIG).isEmpty()) {
      sslContextFactory.setProtocol(config.getString(RestConfig.SSL_PROVIDER_CONFIG));
    }

    sslContextFactory.setRenegotiationAllowed(false);

    return sslContextFactory;
  }

  public static SslContextFactory createSslContextFactoryClient(RestConfig config) {
    SslContextFactory sslContextFactory = new SslContextFactory.Client();
    if (!config.getString(RestConfig.SSL_KEYSTORE_LOCATION_CONFIG).isEmpty()) {
      sslContextFactory.setKeyStorePath(
          config.getString(RestConfig.SSL_KEYSTORE_LOCATION_CONFIG)
      );
      sslContextFactory.setKeyStorePassword(
          config.getPassword(RestConfig.SSL_KEYSTORE_PASSWORD_CONFIG).value()
      );
      sslContextFactory.setKeyManagerPassword(
          config.getPassword(RestConfig.SSL_KEY_PASSWORD_CONFIG).value()
      );
      sslContextFactory.setKeyStoreType(
          config.getString(RestConfig.SSL_KEYSTORE_TYPE_CONFIG)
      );

      if (!config.getString(RestConfig.SSL_KEYMANAGER_ALGORITHM_CONFIG).isEmpty()) {
        sslContextFactory.setKeyManagerFactoryAlgorithm(
            config.getString(RestConfig.SSL_KEYMANAGER_ALGORITHM_CONFIG));
      }
    }

    configureClientAuth(sslContextFactory, config);

    List<String> enabledProtocols = config.getList(RestConfig.SSL_ENABLED_PROTOCOLS_CONFIG);
    if (!enabledProtocols.isEmpty()) {
      sslContextFactory.setIncludeProtocols(enabledProtocols.toArray(new String[0]));
    }

    List<String> cipherSuites = config.getList(RestConfig.SSL_CIPHER_SUITES_CONFIG);
    if (!cipherSuites.isEmpty()) {
      sslContextFactory.setIncludeCipherSuites(cipherSuites.toArray(new String[0]));
    }

    sslContextFactory.setEndpointIdentificationAlgorithm(
        config.getString(RestConfig.SSL_ENDPOINT_IDENTIFICATION_ALGORITHM_CONFIG));

    if (!config.getString(RestConfig.SSL_TRUSTSTORE_LOCATION_CONFIG).isEmpty()) {
      sslContextFactory.setTrustStorePath(
          config.getString(RestConfig.SSL_TRUSTSTORE_LOCATION_CONFIG)
      );
      sslContextFactory.setTrustStorePassword(
          config.getPassword(RestConfig.SSL_TRUSTSTORE_PASSWORD_CONFIG).value()
      );
      sslContextFactory.setTrustStoreType(
          config.getString(RestConfig.SSL_TRUSTSTORE_TYPE_CONFIG)
      );

      if (!config.getString(RestConfig.SSL_TRUSTMANAGER_ALGORITHM_CONFIG).isEmpty()) {
        sslContextFactory.setTrustManagerFactoryAlgorithm(
            config.getString(RestConfig.SSL_TRUSTMANAGER_ALGORITHM_CONFIG)
        );
      }
    }

    sslContextFactory.setProtocol(config.getString(RestConfig.SSL_PROTOCOL_CONFIG));
    if (!config.getString(RestConfig.SSL_PROVIDER_CONFIG).isEmpty()) {
      sslContextFactory.setProtocol(config.getString(RestConfig.SSL_PROVIDER_CONFIG));
    }

    sslContextFactory.setRenegotiationAllowed(false);

    return sslContextFactory;
  }

}