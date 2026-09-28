/*
  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

  Licensed under the Apache License, Version 2.0 (the "License").
  You may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/
package software.amazon.msk.auth.iam.internals.region;

import java.util.Objects;

/**
 * Derives a network-prefix label from an IPv4 address and a CIDR mask width, for use by
 * {@link LookupDnsRegionProvider} when building the TXT lookup name.
 *
 * <p>Given a resolved bootstrap IP (e.g. {@code 10.218.4.7}) and a {@code masking} parameter such
 * as {@code 0.0.0.0/16}, this computes the masked network prefix ({@code 10.218.0.0}) and its
 * dash-encoded label ({@code 10-218-0-0}).</p>
 *
 * <p>Only the prefix length (the {@code /NN} portion) of the {@code masking} parameter is
 * significant; the address portion (e.g. {@code 0.0.0.0}) is ignored — it exists purely to make
 * the parameter read like a familiar CIDR block. The mask is applied to the actual resolved IP.</p>
 *
 * <p>IPv4 only; IPv6 bootstrap addresses are not supported by this scheme. Only octet-aligned
 * prefix lengths ({@code /8}, {@code /16}, {@code /24}, {@code /32}) are supported, so the masked
 * network prefix always falls on a dotted-quad boundary and dash-encodes into a clean DNS label.</p>
 */
final class NetworkPrefix {

    private final int prefixLength;

    private NetworkPrefix(int prefixLength) {
        this.prefixLength = prefixLength;
    }

    /**
     * Parse a {@code masking} parameter of the form {@code A.B.C.D/NN} (or just {@code /NN} or
     * {@code NN}) and extract the prefix length.
     *
     * @param masking the CIDR-style mask parameter.
     * @return the parsed network prefix.
     * @throws IllegalArgumentException if the prefix length is missing, non-numeric, outside
     *                                  {@code 8..32}, or not octet-aligned.
     */
    static NetworkPrefix parse(String masking) {
        Objects.requireNonNull(masking, "masking");
        String trimmed = masking.trim();
        int slash = trimmed.indexOf('/');
        String lenPart = slash >= 0 ? trimmed.substring(slash + 1).trim() : trimmed;
        final int len;
        try {
            len = Integer.parseInt(lenPart);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(
                    "Invalid masking parameter '" + masking + "': missing or invalid prefix length", e);
        }
        if (len < 8 || len > 32) {
            throw new IllegalArgumentException(
                    "Invalid CIDR prefix length " + len + " in '" + masking + "' (must be 8..32)");
        }
        if (len % 8 != 0) {
            throw new IllegalArgumentException(
                    "Unsupported CIDR prefix length /" + len + " in '" + masking + "': only octet-aligned "
                            + "masks (/8, /16, /24, /32) are supported so the network prefix maps cleanly "
                            + "onto dotted-quad / dash-encoded DNS labels");
        }
        return new NetworkPrefix(len);
    }

    int prefixLength() {
        return prefixLength;
    }

    /**
     * Apply this prefix mask to a dotted-quad IPv4 address, returning the masked network address in
     * dotted-quad form (e.g. {@code 10.218.4.7} with /16 -&gt; {@code 10.218.0.0}).
     *
     * @param ipv4 the dotted-quad IPv4 address.
     * @return the masked network address in dotted-quad form.
     */
    String applyMask(String ipv4) {
        long addr = toLong(ipv4);
        long mask = prefixLength == 0 ? 0L : (0xFFFFFFFFL << (32 - prefixLength)) & 0xFFFFFFFFL;
        long network = addr & mask;
        return toDotted(network);
    }

    /**
     * Apply the mask and dash-encode the result for use as a DNS label (e.g. {@code 10.218.4.7}
     * with /16 -&gt; {@code 10-218-0-0}).
     *
     * @param ipv4 the dotted-quad IPv4 address.
     * @return the dash-encoded masked network prefix.
     */
    String toDashedLabel(String ipv4) {
        return applyMask(ipv4).replace('.', '-');
    }

    private static long toLong(String ipv4) {
        String[] parts = ipv4.trim().split("\\.");
        if (parts.length != 4) {
            throw new IllegalArgumentException("Not a valid IPv4 address: '" + ipv4 + "'");
        }
        long result = 0;
        for (String part : parts) {
            final int octet;
            try {
                octet = Integer.parseInt(part);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Not a valid IPv4 address: '" + ipv4 + "'", e);
            }
            if (octet < 0 || octet > 255) {
                throw new IllegalArgumentException(
                        "IPv4 octet out of range in '" + ipv4 + "': " + octet);
            }
            result = (result << 8) | octet;
        }
        return result;
    }

    private static String toDotted(long addr) {
        return String.format("%d.%d.%d.%d",
                (addr >> 24) & 0xFF,
                (addr >> 16) & 0xFF,
                (addr >> 8) & 0xFF,
                addr & 0xFF);
    }
}
