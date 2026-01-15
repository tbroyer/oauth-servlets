package net.ltgt.oauth.common;

import com.nimbusds.openid.connect.sdk.Nonce;
import java.util.List;

/**
 * Supplies nonces usable by the clients in the DPoP proofs.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9449.html#name-resource-server-provided-no">OAuth
 *     2.0 Demonstrating Proof of Possession (DPoP), Section 9. Resource Server-Provided Nonce</a>
 */
public interface DPoPNonceSupplier {

  /**
   * Returns a list of acceptable nonces for verifying DPoP proofs.
   *
   * <p>The list must contain at least one element, otherwise all DPoP proofs will be rejected.
   *
   * <p>The first element will also be returned in a {@code DPoP-Nonce} response header, whereas the
   * following elements represent past values and are only used for verifying the DPoP proofs.
   */
  List<Nonce> getNonces();
}
