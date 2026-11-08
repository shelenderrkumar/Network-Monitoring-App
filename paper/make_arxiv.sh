#!/usr/bin/env bash
# Build the paper and pack an arXiv submission: source, pre-built bibliography and figures.
#   bash paper/make_arxiv.sh   ->  paper/arxiv-submission.tar.gz
set -euo pipefail
cd "$(dirname "$0")"
latexmk -pdf -interaction=nonstopmode -halt-on-error main.tex >/dev/null
tar -czf arxiv-submission.tar.gz main.tex main.bbl figures/*.pdf figures/*.tex
echo "wrote paper/arxiv-submission.tar.gz ($(tar -tzf arxiv-submission.tar.gz | wc -l) files)"
