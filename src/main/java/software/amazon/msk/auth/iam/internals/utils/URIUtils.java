package software.amazon.msk.auth.iam.internals.utils;

import static java.util.stream.Collectors.mapping;
import static java.util.stream.Collectors.toList;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class URIUtils {

  /**
   * Parse the query parameters from the URI.
   *
   * @param url The URI to parse.
   * @return A map of query parameters.
   */
  public static Map<String, List<String>> parseQueryParams(URI url) {
    if (url.getQuery() == null || url.getQuery().isEmpty()) {
      return Collections.emptyMap();
    }
    return Arrays.stream(url.getQuery().split("&"))
        .map(URIUtils::splitQueryParameter)
        .collect(Collectors.groupingBy(SimpleImmutableEntry::getKey, LinkedHashMap::new,
            mapping(Map.Entry::getValue, toList())));
  }

  private static SimpleImmutableEntry<String, String> splitQueryParameter(String it) {
    final int idx = it.indexOf("=");
    final String key = idx > 0 ? it.substring(0, idx) : it;
    final String value = idx > 0 && it.length() > idx + 1 ? it.substring(idx + 1) : null;
    return new SimpleImmutableEntry<>(decodeSilently(key), decodeSilently(value));
  }

  private static String decodeSilently(String s) {
    try {
      return URLDecoder.decode(s, StandardCharsets.UTF_8.name());
    } catch (UnsupportedEncodingException e) {
      throw new RuntimeException(e);
    }
  }
}
