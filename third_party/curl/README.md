# curl build patch

The Apple dependency build uses curl 8.22.0, downloaded from its official release
archive and checked against the pinned SHA-256 in `build-dependencies.sh`.

`location-1xx.patch` carries the existing local fix for informational responses:
a Location in a 103 response must not become the redirect Location of the final
response. It leaves final-response duplicate-header checks intact. The existing
Redfish integration fixture covers 103 followed by a different final Location,
conflicting final Location fields, and an unfollowed external Location.

This is a locally patched dependency, not an unmodified upstream build. The same
unconditional Location processing is present in the upstream 8.23.0 source.

References:

- https://www.rfc-editor.org/rfc/rfc8297.html#section-2
- https://github.com/curl/curl/blob/curl-8_22_0/lib/http.c
- https://github.com/curl/curl/blob/curl-8_23_0/lib/http.c

curl is distributed under the curl license. The build copies the release's
COPYING into the dependency prefix and the app's Licenses directory.
