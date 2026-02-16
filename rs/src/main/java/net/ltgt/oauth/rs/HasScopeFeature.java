/*
 * Copyright © 2026 Thomas Broyer
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
package net.ltgt.oauth.rs;

import jakarta.ws.rs.container.DynamicFeature;
import jakarta.ws.rs.container.ResourceInfo;
import jakarta.ws.rs.core.FeatureContext;
import jakarta.ws.rs.ext.Provider;

/** Applies the {@link HasScopeFilter} to any resource annotated with {@link HasScope}. */
@Provider
public class HasScopeFeature implements DynamicFeature {
  @Override
  public void configure(ResourceInfo resourceInfo, FeatureContext context) {
    var scope = resourceInfo.getResourceMethod().getAnnotation(HasScope.class);
    if (scope == null) {
      scope = resourceInfo.getResourceClass().getAnnotation(HasScope.class);
    }
    if (scope != null) {
      context.register(new HasScopeFilter(scope.value()));
    }
  }
}
