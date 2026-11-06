"""Build the arXiv LaTeX source and PDF from body.md + meta.yaml.

1. Resolve cross-references (pandoc-crossref is not required).
2. pandoc -> PivotBench.tex (natbib).
3. Replace every pandoc longtable with a non-breaking table float whose column
   spec is chosen per table, so headers never hyphenate and numbers never wrap.
4. pdflatex + bibtex + pdflatex x2.
"""
import re
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent

SPECS = {
    "tbl:classes": r"@{}l r >{\raggedright\arraybackslash}p{5.5cm} >{\raggedright\arraybackslash}p{4.6cm}@{}",
    "tbl:conditions": r"@{}l l >{\raggedright\arraybackslash}p{3.5cm} >{\raggedright\arraybackslash}p{6.5cm}@{}",
    "tbl:modelside": r"@{}l r l r l@{}",
    "tbl:detection": r"@{}l r r r r r l r@{}",
    "tbl:monitors": r"@{}l r r r r r@{}",
    "tbl:oracle": r"@{}l r r r r r l r@{}",
    "tbl:e2e": r"@{}l l l r r r@{}",
    "tbl:planner": r"@{}l l l l l@{}",
    "tbl:gateaware": r"@{}l r r r r@{}",
    "tbl:hops": r"@{}l l@{}",
    "tbl:families": r"@{}l l l l@{}",
    "tbl:familygates": r"@{}l l r@{}",
    "tbl:familyjudges": r"@{}l l l l l@{}",
    "tbl:perbehaviour": r"@{}l r r r r@{}",
    "tbl:dynamic": r"@{}l l r r@{}",
}


COMPACT = {"tbl:detection", "tbl:monitors", "tbl:oracle"}


def preprocess():
    s = (HERE / "body.md").read_text()
    s = re.sub(r"§\[-@(sec:[\w-]+)\]", r"§\\ref{\1}", s)
    s = re.sub(r"(Appendix|Figure|Table) \[-@((?:sec|fig|tbl):[\w-]+)\]", r"\1 \\ref{\2}", s)
    s = re.sub(r"(\nTable: .*?) \{#(tbl:[\w-]+)\}", r"\1 \\label{\2}", s)
    assert "[-@" not in s, "unresolved cross-reference"
    (HERE / "body_pp.md").write_text(s)


def balanced(s, i):
    """s[i] == '{'; return index of the matching '}'."""
    depth = 0
    for j in range(i, len(s)):
        if s[j] == "{":
            depth += 1
        elif s[j] == "}":
            depth -= 1
            if depth == 0:
                return j
    raise ValueError("unbalanced braces")


def strip_minipages(x):
    x = re.sub(r"\\begin\{minipage\}\[b\]\{\\linewidth\}\\raggedright\s*", "", x)
    x = re.sub(r"\s*\\end\{minipage\}", "", x)
    return x.strip()


def convert_tables(tex):
    out, pos, n = [], 0, 0
    while True:
        a = tex.find(r"\begin{longtable}", pos)
        if a < 0:
            out.append(tex[pos:])
            break
        b = tex.find(r"\end{longtable}", a) + len(r"\end{longtable}")
        block = tex[a:b]
        c0 = block.find(r"\caption{")
        c1 = balanced(block, c0 + len(r"\caption"))
        caption = block[c0 + len(r"\caption{"):c1].strip()
        label = re.search(r"\\label\{(tbl:[\w-]+)\}", caption).group(1)
        rest = block[c1:]
        h0 = rest.find(r"\toprule\noalign{}") + len(r"\toprule\noalign{}")
        h1 = rest.find(r"\midrule\noalign{}")
        header = strip_minipages(rest[h0:h1])
        if r"\endlastfoot" in rest:
            body = rest[rest.find(r"\endlastfoot") + len(r"\endlastfoot"):]
        else:
            body = rest[rest.find(r"\endhead") + len(r"\endhead"):]
        body = body.replace(r"\end{longtable}", "").replace(r"\bottomrule\noalign{}", "").strip()
        spec = SPECS[label]
        out.append(tex[pos:a])
        out.append("\n".join([
            r"\begin{table}[!htbp]", r"\centering" + (r"\footnotesize\setlength{\tabcolsep}{4pt}" if label in COMPACT else r"\small"),
            r"\caption{" + caption + "}",
            r"\begin{tabular}{" + spec + "}", r"\toprule", header, r"\midrule", body, r"\bottomrule",
            r"\end{tabular}", r"\end{table}"]))
        pos, n = b, n + 1
    return "".join(out), n


def main():
    preprocess()
    subprocess.run(["pandoc", "meta.yaml", "body_pp.md", "-s", "--natbib", "-o", "PivotBench.tex"], cwd=HERE, check=True)
    tex = (HERE / "PivotBench.tex").read_text()
    tex, n = convert_tables(tex)
    tex = tex.replace(r"\begin{figure}", r"\begin{figure}[!htbp]") if r"\begin{figure}[" not in tex else tex
    (HERE / "PivotBench.tex").write_text(tex)
    print("tables converted:", n)
    for cmd in (["pdflatex", "-interaction=nonstopmode", "PivotBench.tex"], ["bibtex", "PivotBench"],
                ["pdflatex", "-interaction=nonstopmode", "PivotBench.tex"],
                ["pdflatex", "-interaction=nonstopmode", "PivotBench.tex"]):
        subprocess.run(cmd, cwd=HERE, capture_output=True, text=True)
    log = (HERE / "PivotBench.log").read_text(errors="replace")
    errs = [l for l in log.splitlines() if l.startswith("!")]
    over = re.findall(r"Overfull \\hbox \(([\d.]+)pt too wide\)[^\n]*lines (\d+)--(\d+)", log)
    print("errors:", errs[:5])
    print("overfull >1pt:", [o for o in over if float(o[0]) > 1.0])
    print("undefined refs:", "undefined" in log.lower() and [l for l in log.splitlines() if "undefined" in l.lower()][:5])


if __name__ == "__main__":
    main()
