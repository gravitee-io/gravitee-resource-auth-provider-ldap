/**
 * Copyright (C) 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.resource.authprovider.ldap;

import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.handler.Handler;
import io.gravitee.resource.authprovider.api.Authentication;
import io.gravitee.resource.authprovider.api.AuthenticationProviderResource;
import io.gravitee.resource.authprovider.ldap.cache.LRUCache;
import io.gravitee.resource.authprovider.ldap.configuration.LdapAuthenticationProviderResourceConfiguration;
import java.time.Duration;
import java.util.Map;
import java.util.stream.Collectors;
import org.ldaptive.*;
import org.ldaptive.auth.*;
import org.ldaptive.pool.*;
import org.ldaptive.provider.unboundid.UnboundIDProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
public class LdapAuthenticationProviderResource extends AuthenticationProviderResource<LdapAuthenticationProviderResourceConfiguration> {

    private final Logger logger = LoggerFactory.getLogger(LdapAuthenticationProviderResource.class);

    private static final String LDAP_SEPARATOR = ",";

    private PooledConnectionFactory pooledConnectionFactory, searchPooledConnectionFactory;

    private Authenticator authenticator;

    private LRUCache cache;

    private String[] userAttributes = ReturnAttributes.ALL_USER.value();

    @Override
    public void authenticate(String username, String password, ExecutionContext context, Handler<Authentication> handler) {
        Authentication authentication = cache.get(username);

        if (authentication == null) {
            try {
                AuthenticationResponse response = authenticator.authenticate(
                    new AuthenticationRequest(username, new Credential(password), userAttributes)
                );
                if (response.getResult()) {
                    LdapEntry userEntry = response.getLdapEntry();

                    authentication = new Authentication(userEntry.getDn());

                    Map<String, Object> attributes = userEntry
                        .getAttributes()
                        .stream()
                        .collect(Collectors.toMap(LdapAttribute::getName, LdapAttribute::getStringValue));

                    authentication.setAttributes(attributes);

                    cache.put(username, authentication);

                    handler.handle(authentication);
                } else {
                    logger.debug("Failed to authenticate user[{}] message[{}]", username, response.getMessage());
                    handler.handle(null);
                }
            } catch (LdapException ldapEx) {
                logger.error("An error occurs while trying to authenticate a user from LDAP [{}]", name(), ldapEx);
                handler.handle(null);
            }
        } else {
            handler.handle(authentication);
        }
    }

    @Override
    protected void doStart() throws Exception {
        super.doStart();

        pooledConnectionFactory = bindPooledConnectionFactory();
        searchPooledConnectionFactory = searchPooledConnectionFactory();

        logger.info("Init LDAP connection to source[{}]", configuration().getContextSourceUrl());
        if (pooledConnectionFactory != null) {
            pooledConnectionFactory.getConnectionPool().initialize();
        }

        if (searchPooledConnectionFactory != null) {
            searchPooledConnectionFactory.getConnectionPool().initialize();
        }

        PooledSearchDnResolver dnResolver = new PooledSearchDnResolver(searchPooledConnectionFactory);
        String userSearchBase = configuration().getUserSearchBase();
        dnResolver.setBaseDn(configuration().getContextSourceBase());
        if (userSearchBase != null && !userSearchBase.isEmpty()) {
            dnResolver.setBaseDn(userSearchBase + LDAP_SEPARATOR + dnResolver.getBaseDn());
        }
        // unable *={0} authentication filter (ldaptive use *={user})
        dnResolver.setUserFilter(configuration().getUserSearchFilter().replaceAll("\\{0\\}", "{user}"));
        dnResolver.setSubtreeSearch(true);
        dnResolver.setAllowMultipleDns(false);

        AbstractAuthenticationHandler authHandler = new PooledBindAuthenticationHandler(pooledConnectionFactory);
        PooledSearchEntryResolver pooledSearchEntryResolver = new PooledSearchEntryResolver(pooledConnectionFactory);

        authenticator = new Authenticator(dnResolver, authHandler);
        authenticator.setEntryResolver(pooledSearchEntryResolver);

        cache =
            new LRUCache(
                configuration().getCacheMaxElements(),
                Duration.ofMillis(configuration().getCacheTimeToLive()),
                Duration.ofMinutes(1)
            );

        if (configuration().getAttributes() != null && !configuration().getAttributes().isEmpty()) {
            userAttributes = new String[configuration().getAttributes().size()];
            userAttributes = configuration().getAttributes().toArray(userAttributes);
        }
    }

    @Override
    protected void doStop() throws Exception {
        super.doStop();

        if (pooledConnectionFactory != null) {
            logger.info("Closing LDAP connections to source[{}]", configuration().getContextSourceUrl());
            pooledConnectionFactory.getConnection().close();
            pooledConnectionFactory.getConnectionPool().close();
        }

        if (searchPooledConnectionFactory != null) {
            logger.info("Closing LDAP search connections to source[{}]", configuration().getContextSourceUrl());
            searchPooledConnectionFactory.getConnection().close();
            searchPooledConnectionFactory.getConnectionPool().close();
        }

        if (cache != null) {
            cache.clear();
            cache.close();
        }
    }

    private ConnectionPool bindConnectionPool() {
        PoolConfig poolConfig = new PoolConfig();
        poolConfig.setMinPoolSize(configuration().getMinPoolSize());
        poolConfig.setMaxPoolSize(configuration().getMaxPoolSize());
        poolConfig.setValidatePeriodically(true);
        BlockingConnectionPool connectionPool = new BlockingConnectionPool(poolConfig, (DefaultConnectionFactory) bindConnectionFactory());
        connectionPool.setValidator(new SearchValidator());

        return connectionPool;
    }

    private ConnectionFactory bindConnectionFactory() {
        UnboundIDProvider unboundIDProvider = new UnboundIDProvider();
        DefaultConnectionFactory connectionFactory = new DefaultConnectionFactory();
        connectionFactory.setConnectionConfig(connectionConfig());
        connectionFactory.setProvider(unboundIDProvider);
        return connectionFactory;
    }

    private ConnectionConfig connectionConfig() {
        ConnectionConfig connectionConfig = new ConnectionConfig();
        connectionConfig.setConnectTimeout(Duration.ofMillis(configuration().getConnectTimeout()));
        connectionConfig.setResponseTimeout(Duration.ofMillis(configuration().getResponseTimeout()));
        connectionConfig.setLdapUrl(configuration().getContextSourceUrl());
        connectionConfig.setUseStartTLS(configuration().isUseStartTLS());
        BindConnectionInitializer connectionInitializer = new BindConnectionInitializer(
            configuration().getContextSourceUsername(),
            new Credential(configuration().getContextSourcePassword())
        );
        connectionConfig.setConnectionInitializer(connectionInitializer);
        return connectionConfig;
    }

    private PooledConnectionFactory searchPooledConnectionFactory() {
        return new PooledConnectionFactory(searchConnectionPool());
    }

    private PooledConnectionFactory bindPooledConnectionFactory() {
        return new PooledConnectionFactory(bindConnectionPool());
    }

    private ConnectionPool searchConnectionPool() {
        PoolConfig poolConfig = new PoolConfig();
        poolConfig.setMinPoolSize(configuration().getMinPoolSize());
        poolConfig.setMaxPoolSize(configuration().getMaxPoolSize());
        poolConfig.setValidatePeriodically(true);
        BlockingConnectionPool connectionPool = new BlockingConnectionPool(
            poolConfig,
            (DefaultConnectionFactory) searchConnectionFactory()
        );
        connectionPool.setValidator(new SearchValidator());
        return connectionPool;
    }

    private ConnectionFactory searchConnectionFactory() {
        UnboundIDProvider unboundIDProvider = new UnboundIDProvider();
        DefaultConnectionFactory connectionFactory = new DefaultConnectionFactory();
        connectionFactory.setConnectionConfig(connectionConfig());
        connectionFactory.setProvider(unboundIDProvider);
        return connectionFactory;
    }
}
