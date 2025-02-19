package net.ltgt.oauth.rs;

import jakarta.ws.rs.container.DynamicFeature;
import jakarta.ws.rs.container.ResourceInfo;
import jakarta.ws.rs.core.FeatureContext;
import jakarta.ws.rs.ext.Provider;

/** Applies the {@link HasRoleFilter} to any resource annotated with {@link HasRole}. */
@Provider
public class HasRoleFeature implements DynamicFeature {
  @Override
  public void configure(ResourceInfo resourceInfo, FeatureContext context) {
    var role = resourceInfo.getResourceMethod().getAnnotation(HasRole.class);
    if (role == null) {
      role = resourceInfo.getResourceClass().getAnnotation(HasRole.class);
    }
    if (role != null) {
      context.register(new HasRoleFilter(role.value()));
    }
  }
}
