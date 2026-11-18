# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Sends provider A's token from BOUND_TOKEN_A to host $1: on port $2 at a
# path its profile binds, on port $3, which provider B's profile binds, and on
# port $2 at a path outside the binding. Prints the first response body and
# the other two statuses. Never prints the token.
host="$1" port_a="$2" port_b="$3"

http_request() {
  local port="$1" path="$2" status_line line
  HTTP_STATUS= HTTP_BODY=
  if ! exec 3<>"/dev/tcp/$host/$port"; then
    HTTP_STATUS=connect-denied
    return 1
  fi
  printf 'GET %s HTTP/1.1\r\nHost: %s:%s\r\nAuthorization: Bearer %s\r\nConnection: close\r\n\r\n' \
    "$path" "$host" "$port" "$BOUND_TOKEN_A" >&3
  IFS= read -r status_line <&3 || return 1
  status_line="${status_line%$'\r'}"
  HTTP_STATUS="${status_line#* }"
  HTTP_STATUS="${HTTP_STATUS%% *}"
  while IFS= read -r line <&3; do
    line="${line%$'\r'}"
    [[ -z "$line" ]] && break
  done
  while IFS= read -r line <&3 || [[ -n "$line" ]]; do HTTP_BODY+="$line"; done
  exec 3>&- 3<&-
}

http_request "$port_a" /allowed/check; allowed="$HTTP_BODY"
http_request "$port_b" /allowed/check || true; endpoint_denied="$HTTP_STATUS"
http_request "$port_a" /other/check; path_denied="$HTTP_STATUS"
printf 'ALLOWED=%s ENDPOINT_DENIED=%s PATH_DENIED=%s\n' "$allowed" "$endpoint_denied" "$path_denied"
