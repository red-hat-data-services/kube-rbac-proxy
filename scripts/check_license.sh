#!/bin/sh

licRes=$(
	find . -type f -iname '*.go' ! -path '*/vendor/*' -exec sh -c '
		for file do
			head -n5 "${file}" | grep -Eq "(Copyright|generated|GENERATED)" || printf "  %s\n" "${file}"
		done
	' sh {} +
)
if [ -n "${licRes}" ]; then
	printf "license header checking failed:\n%s\n" "${licRes}"
	exit 255
fi
