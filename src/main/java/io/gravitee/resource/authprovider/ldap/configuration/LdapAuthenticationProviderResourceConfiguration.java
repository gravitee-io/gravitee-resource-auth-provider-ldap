/*
 * Copyright © 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.resource.authprovider.ldap.configuration;

import io.gravitee.plugin.annotation.ConfigurationEvaluator;
import io.gravitee.resource.api.ResourceConfiguration;
import io.gravitee.secrets.api.annotation.Secret;
import io.gravitee.secrets.api.el.FieldKind;
import java.time.Duration;
import java.util.List;
import lombok.Data;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
@Data
@ConfigurationEvaluator
public class LdapAuthenticationProviderResourceConfiguration implements ResourceConfiguration {

    @Secret
    private String contextSourceUrl;

    private boolean useStartTLS;

    @Secret
    private String contextSourceBase;

    @Secret
    private String contextSourceUsername;

    @Secret(FieldKind.PASSWORD)
    private String contextSourcePassword;

    private String userSearchBase = "";

    private String userSearchFilter;

    private List<String> attributes;

    private int cacheMaxElements = 100;

    private int cacheTimeToLive = 60000;

    private Long connectTimeout = 5000L;

    private Long responseTimeout = 5000L;

    private Integer minPoolSize = 5;

    private Integer maxPoolSize = 15;

    private long cacheChecksMs = Duration.ofMinutes(1).toMillis();
}
