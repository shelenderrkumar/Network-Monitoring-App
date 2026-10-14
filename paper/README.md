# Paper: Blocking the First Connection

ACM `acmart` (sigconf) source for the workshop paper on DPI Guard.

```bash
python paper/figures.py                  # figures from bench/results/*.csv (needs matplotlib + LaTeX)
cd paper && latexmk -pdf main.tex        # -> main.pdf
```

Requires TeX Live with `acmart`, `libertine`, `newtx`, `cm-super` (Ubuntu:
`texlive-publishers texlive-fonts-extra texlive-latex-extra texlive-plain-generic cm-super`).
The same folder can be imported into Overleaf as-is (upload `main.tex`, `refs.bib`, `figures/`).

Red `[TODO: …]` markers flag text that waits on planned experiments.
