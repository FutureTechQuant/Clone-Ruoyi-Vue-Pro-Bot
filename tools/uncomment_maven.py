import re
from pathlib import Path

TARGET_POM = Path("apps/future-server/pom.xml")

COMMENTED_XML_LINE = re.compile(r'^(\s*)<!--\s*(<[^!].*?)\s*-->\s*$')
COMMENTED_XML_OPEN = re.compile(r'^(\s*)<!--\s*(<[^!].*?)\s*$')
COMMENTED_XML_CLOSE = re.compile(r'^(.*?)(\s*)-->\s*$')

DEP_START = re.compile(r'^\s*<!--\s*<dependency>\s*-->\s*$|^\s*<!--\s*<dependency>\s*$')
DEP_END = re.compile(r'.*</dependency>.*')
ARTIFACT_ID = re.compile(r'<artifactId>\s*([^<]+)\s*</artifactId>')

ENABLE_ARTIFACTS = {
    "future-module-member-biz",
    "future-module-report-biz",
    "future-module-bpm-biz",
    "future-module-pay-biz",
    "future-module-mp-biz",
    "future-module-product-biz",
    "future-module-promotion-biz",
    "future-module-trade-biz",
    "future-module-statistics-biz",
    "future-module-crm-biz",
    "future-module-erp-biz",
    "future-module-ai-biz",
    # "future-module-iot-biz",
}

def uncomment_line(line: str) -> str:
    m = COMMENTED_XML_LINE.match(line)
    if m:
        return f"{m.group(1)}{m.group(2)}\n"
    m = COMMENTED_XML_OPEN.match(line)
    if m:
        return f"{m.group(1)}{m.group(2)}\n"
    m = COMMENTED_XML_CLOSE.match(line)
    if m:
        return f"{m.group(1).rstrip()}\n"
    return line

def get_artifact_id(block_text: str):
    m = ARTIFACT_ID.search(block_text)
    return m.group(1).strip() if m else None

def should_enable_dep(block_text: str) -> bool:
    aid = get_artifact_id(block_text)
    return aid in ENABLE_ARTIFACTS

def process_pom(pom: Path) -> bool:
    lines = pom.read_text(encoding="utf-8").splitlines(True)
    out = []
    changed = False
    dep_buf = None

    for line in lines:
        if dep_buf is None:
            if DEP_START.match(line):
                dep_buf = [line]
                continue
            out.append(line)
        else:
            dep_buf.append(line)
            if DEP_END.match(line):
                block_text = "".join(dep_buf)
                if should_enable_dep(block_text):
                    new_block = [uncomment_line(x) for x in dep_buf]
                    out.extend(new_block)
                    if "".join(new_block) != block_text:
                        changed = True
                else:
                    out.extend(dep_buf)
                dep_buf = None

    if dep_buf is not None:
        out.extend(dep_buf)

    if changed:
        pom.write_text("".join(out), encoding="utf-8")
    return changed

def main():
    if not TARGET_POM.exists():
        print(f"skip, not found: {TARGET_POM}")
        return

    if process_pom(TARGET_POM):
        print(f"updated: {TARGET_POM}")
    else:
        print(f"no changes: {TARGET_POM}")

if __name__ == "__main__":
    main()
