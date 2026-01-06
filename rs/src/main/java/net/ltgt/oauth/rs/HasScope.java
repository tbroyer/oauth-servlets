package net.ltgt.oauth.rs;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Ensures the access token {@linkplain net.ltgt.oauth.common.TokenPrincipal#hasScope(String) has a
 * given scope}
 *
 * @see HasScopeFeature
 * @see HasScopeFilter
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE, ElementType.METHOD})
public @interface HasScope {
  String value();
}
