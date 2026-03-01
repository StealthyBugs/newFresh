#!/bin/bash
while IFS= read -r host; do
  [[ -z "$host" ]] && continue
  c=$(curl -sk -o /dev/null -w '%{http_code}' "$host")
  a=$(awscurl --service execute-api --region us-east-1 -v "$host" 2>&1 | sed -n "s/.*Response code: \([0-9]*\).*/\1/p")
  [[ "$c" != "$a" ]] && echo "$host curl=$c awscurl=$a"
done < probed.txt
