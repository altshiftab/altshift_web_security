#!/bin/sh
# Fetches the vendored bypass lists again, at the given commits or at the head of each upstream default branch.
# Usage: refresh.sh [CSP_EVALUATOR_COMMIT [CSP_TOOLKIT_COMMIT]]
set -eu

cd "$(dirname "$0")"

evaluator_repository=https://github.com/google/csp-evaluator
toolkit_repository=https://github.com/sampsonc/csp_toolkit

evaluator_commit=${1:-$(git ls-remote "$evaluator_repository.git" HEAD | cut -f1)}
toolkit_commit=${2:-$(git ls-remote "$toolkit_repository.git" HEAD | cut -f1)}

for commit in "$evaluator_commit" "$toolkit_commit"; do
    if ! printf '%s\n' "$commit" | grep -Eq '^[0-9a-f]{40}$'; then
        echo "refresh.sh: '$commit' is not a full commit hash" >&2
        exit 1
    fi
done

evaluator_raw=https://raw.githubusercontent.com/google/csp-evaluator/$evaluator_commit
toolkit_raw=https://raw.githubusercontent.com/sampsonc/csp_toolkit/$toolkit_commit

download_directory=$(mktemp -d)
trap 'rm -rf "$download_directory"' EXIT

fetch() {
    curl --fail --silent --show-error --location --output "$download_directory/$2" "$1"
}

fetch "$evaluator_raw/allowlist_bypasses/jsonp.ts" jsonp.ts
fetch "$evaluator_raw/allowlist_bypasses/angular.ts" angular.ts
fetch "$evaluator_raw/LICENSE" evaluator_license
fetch "$toolkit_raw/src/csp_toolkit/data/cdn_gadgets.json" cdn_gadgets.json
fetch "$toolkit_raw/src/csp_toolkit/bypass.py" bypass.py
fetch "$toolkit_raw/LICENSE" toolkit_license

staging_directory=$download_directory/staging
mkdir "$staging_directory"

# write_list FILE SHAPE HEADER: stages the entries read from standard input under a header, refusing an empty list
# or an entry not matching the extended regular expression SHAPE.
write_list() {
    entries=$(cat)
    if [ -z "$entries" ]; then
        echo "refresh.sh: no entries for $1; has the upstream file changed shape?" >&2
        exit 1
    fi
    if printf '%s\n' "$entries" | grep -Evq "$2"; then
        echo "refresh.sh: entries for $1 not matching $2:" >&2
        printf '%s\n' "$entries" | grep -Ev "$2" >&2
        exit 1
    fi
    printf '%s\n%s\n' "$3" "$entries" > "$staging_directory/$1"
}

# typescript_array FILE NAME: the single-quoted strings of the exported array NAME.
typescript_array() {
    sed -n "/export const $2\\b/,/];/p" "$download_directory/$1" | grep -o "'[^']*'" | tr -d "'"
}

url_shape='^//[a-z0-9.-]+(/[^[:space:]]*)?$'
host_shape='^[a-z0-9.-]+$'

evaluator_notice="# Copyright 2016 Google Inc. Licensed under the Apache License, Version 2.0; see NOTICE and LICENSE-csp-evaluator."
toolkit_notice="# Copyright (c) 2026 Carl Sampson. Licensed under the MIT License; see NOTICE and LICENSE-csp-toolkit."

typescript_array jsonp.ts URLS | write_list csp_evaluator_jsonp.txt "$url_shape" \
    "# The URLS array of allowlist_bypasses/jsonp.ts in $evaluator_repository at $evaluator_commit, with the TypeScript around it removed.
$evaluator_notice"
typescript_array jsonp.ts NEEDS_EVAL | write_list csp_evaluator_jsonp_needs_eval.txt "$host_shape" \
    "# The NEEDS_EVAL array of allowlist_bypasses/jsonp.ts in $evaluator_repository at $evaluator_commit, with the TypeScript around it removed.
$evaluator_notice"
typescript_array angular.ts URLS | write_list csp_evaluator_angular.txt "$url_shape" \
    "# The URLS array of allowlist_bypasses/angular.ts in $evaluator_repository at $evaluator_commit, with the TypeScript around it removed.
$evaluator_notice"

sed -n '/^_ARBITRARY_HOSTING_DOMAINS = frozenset(/,/^)/p' "$download_directory/bypass.py" | grep -o '"[^"]*"' | tr -d '"' |
    write_list csp_toolkit_arbitrary_hosting.txt "$host_shape" \
        "# The _ARBITRARY_HOSTING_DOMAINS set of src/csp_toolkit/bypass.py in $toolkit_repository at $toolkit_commit, with the Python around it removed.
$toolkit_notice"

cp "$download_directory/cdn_gadgets.json" "$staging_directory/csp_toolkit_cdn_gadgets.json"
cp "$download_directory/evaluator_license" "$staging_directory/LICENSE-csp-evaluator"
cp "$download_directory/toolkit_license" "$staging_directory/LICENSE-csp-toolkit"

sed \
    -e "s|^CSP Evaluator commit: .*|CSP Evaluator commit: $evaluator_commit|" \
    -e "s|^csp-toolkit commit: .*|csp-toolkit commit: $toolkit_commit|" \
    NOTICE > "$staging_directory/NOTICE"

# Nothing is replaced until everything is fetched and extracted, so a failure leaves the lists and NOTICE agreeing.
for staged in "$staging_directory"/*; do
    mv "$staged" .
done

echo "CSP Evaluator $evaluator_commit, csp-toolkit $toolkit_commit"
