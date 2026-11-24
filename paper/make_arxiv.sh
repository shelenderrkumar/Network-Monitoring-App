#!/usr/bin/env bash
# Build both versions of the paper and pack the arXiv submission.
#   bash paper/make_arxiv.sh
#     -> paper/main-review.pdf         supervisor copy ("Draft for internal review")
#     -> paper/main.pdf                arXiv version (no subtitle)
#     -> paper/arxiv-submission.tar.gz source, pre-built bibliography and figures
# The arXiv package is refused while the co-author placeholder is still in main.tex.
set -euo pipefail
cd "$(dirname "$0")"
latexmk -pdf -interaction=nonstopmode -halt-on-error main.tex >/dev/null
latexmk -pdf -interaction=nonstopmode -halt-on-error -jobname=main-review \
  -pdflatex='pdflatex %O "\\def\\REVIEWCOPY{}\\input{%S}"' main.tex >/dev/null
echo "built paper/main.pdf (arXiv) and paper/main-review.pdf (supervisor copy)"
if grep -q "AUTHORS-PLACEHOLDER" main.tex; then
  echo "NOT packing for arXiv: confirm the authors and remove the placeholder in main.tex first." >&2
  exit 1
fi
tar -czf arxiv-submission.tar.gz main.tex main.bbl figures/*.pdf figures/*.tex
echo "wrote paper/arxiv-submission.tar.gz ($(tar -tzf arxiv-submission.tar.gz | wc -l) files)"
