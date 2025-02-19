package net.ltgt.oauth.rs;

import jakarta.ws.rs.container.DynamicFeature;
import jakarta.ws.rs.container.ResourceInfo;
import jakarta.ws.rs.core.FeatureContext;

/** Applies the {@link HasScopeFilter} to any resource annotated with {@link HasScope}. */
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
