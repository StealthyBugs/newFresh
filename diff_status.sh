#!/bin/bash
while IFS= read -r host; do
  [[ -z "$host" ]] && continue
  c=$(curl -sk -o /dev/null -w '%{http_code}' "$host")
  a=$(awscurl --service execute-api --region us-east-1 -o /dev/null -w '%{http_code}' "$host" 2>/dev/null)
  [[ "$c" != "$a" ]] && echo "$host curl=$c awscurl=$a"
done < probed.txt
