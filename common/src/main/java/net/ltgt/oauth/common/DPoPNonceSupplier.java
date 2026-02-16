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
