package net.ltgt.oauth.rs;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Ensures the user {@linkplain net.ltgt.oauth.common.TokenPrincipal#hasRole has a given role}
 *
 * @see HasRoleFeature
 * @see HasRoleFilter
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE, ElementType.METHOD})
public @interface HasRole {
  String value();
}
