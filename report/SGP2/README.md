# IRIS SGP2 report and Overleaf source

The PDF follows the supplied UAEU SGP2 structure and synthesizes the supplied SGP1 report with the inspected implementation and saved Colab results. It does not present SGP1 plans as completed SGP2 work.

## Open in Overleaf

Upload `IRIS_SGP2_Overleaf.zip` as a new Overleaf project. Select `main.tex` and pdfLaTeX; the project uses BibTeX with author-year citations. All figures and the reused SGP1 CIT logo are included. No Python execution is required to compile the supplied figures.

For local compilation, run `latexmk -pdf main.tex`. Optional figure regeneration uses `python make_figures.py` with matplotlib and NumPy. `Evidence/metadata.json` and `Evidence/threshold_search.json` are exact copies of the supplied model's saved evaluation evidence; no model weights or private runtime keys are included.

## Confirm before submission

- Confirm the semester: the supplied SGP1 report and SGP2 template both say **Spring 2026**, but the trained-model evidence is dated **25 October 2026**. The cover retains Spring 2026 and clearly flags it; it is not silently backdated.
- Agree on actual SGP2 task percentages, enter them in Chapter 7 and collect signatures. SGP1 percentages are not reused as unverified SGP2 contributions.
- Review the AI-assisted draft with the team/advisor and follow the institution's applicable authorship/disclosure rules.
- Rehearse in a real browser; controller tests are not visual browser verification. Add only genuine successful screenshots if required by the advisor. The current report uses reproducible diagrams and data plots, not invented dashboard screenshots.
- The Gantt chart is a **proposed relative sequence**, not a fabricated completed calendar. Replace it with team-confirmed actual dates if available.

## Evidence boundaries

Model 1 synthetic-test accuracy is 94.07%, macro-F1 0.9405, and benign FPR 15.56%. Model 2 micro-F1 is 0.9542, with positive test support for only six of 30 controls. Both models remain unreleased shadow candidates. The 177 passing Python regressions and 20 controller scenarios establish software behavior on supplied fixtures, not real-world detection effectiveness.

The active demo uses a standard-library loopback HTTP server, HTML/JavaScript and SQLite, not the separately prepared FastAPI service or the earlier Streamlit plan. Live vendor connectors, encryption/SSO, two-second latency, 24/7 availability and real-company validation are not claimed.

The PDF contains all seven chapters, executive summary, automatic contents/list of tables/list of figures, references and appendices. Tables and figures are globally numbered, referenced in the text, and have captions above/below respectively. All charts are based on saved project measurements or are explicitly labeled conceptual/proposed diagrams.
