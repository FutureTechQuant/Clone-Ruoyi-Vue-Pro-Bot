#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import shutil
from pathlib import Path

# ====== 可按需改的常量 ======
ROOT_GROUP_ID = "cn.iocoder.boot"
ROOT_ARTIFACT_ID = "future"
ROOT_POM = Path("pom.xml")

# 目标根 modules（会写入 root pom.xml 的 <modules>）
ROOT_MODULES_XML = """<modules>
        <module>platform/future-dependencies</module>
        <module>platform/future-framework</module>
        <module>apps/future-server</module>
        <module>modules</module>
    </modules>"""

# 目录移动计划：key=旧目录（相对 repo 根），value=新目录
# 注意：这里只移动"顶层模块目录"。模块内部结构保持原样。
MOVE_PLAN = {
    "future-dependencies": "platform/future-dependencies",
    "future-framework": "platform/future-framework",
    "future-server": "apps/future-server",

    "future-module-system": "modules/core/system/future-module-system",
    "future-module-infra": "modules/core/infra/future-module-infra",

    "future-module-crm": "modules/biz/crm/future-module-crm",
    "future-module-erp": "modules/biz/erp/future-module-erp",
    "future-module-mall": "modules/biz/mall/future-module-mall",

    "future-module-member": "modules/extend/member/future-module-member",
    "future-module-bpm": "modules/extend/bpm/future-module-bpm",
    "future-module-report": "modules/extend/report/future-module-report",
    "future-module-mp": "modules/extend/mp/future-module-mp",
    "future-module-pay": "modules/extend/pay/future-module-pay",
    "future-module-ai": "modules/extend/ai/future-module-ai",

    # IoT：你可以先移动目录但不加入聚合构建（见下面 extend_modules）
    "future-module-iot": "modules/extend/iot/future-module-iot",
}

# 是否把 IoT 加入聚合构建（true 就会参与 mvn package）
ENABLE_IOT_IN_AGGREGATOR = True


# ====== 工具函数 ======
def ensure_dir(p: Path):
    p.mkdir(parents=True, exist_ok=True)


def move_dir(src: Path, dst: Path):
    """
    尽量"可重复运行"：
    - src 不存在：跳过
    - dst 已存在：跳过（认为已经移动过）
    """
    if not src.exists():
        print(f"ℹ️  skip (not found): {src}")
        return
    if dst.exists():
        print(f"ℹ️  skip (already exists): {dst}")
        return
    ensure_dir(dst.parent)
    shutil.move(str(src), str(dst))
    print(f"✅ moved: {src} -> {dst}")


def relpath_to_root(from_dir: Path) -> str:
    rp = os.path.relpath(ROOT_POM.resolve(), from_dir.resolve())
    return rp.replace("\\", "/")


def patch_root_modules(root_pom: Path):
    txt = root_pom.read_text(encoding="utf-8")

    # 只替换第一个 <modules>...</modules>（根 pom 一般只有一个）
    patched, n = re.subn(r"<modules>.*?</modules>", ROOT_MODULES_XML, txt, count=1, flags=re.DOTALL)
    if n != 1:
        raise RuntimeError("❌ root pom.xml: <modules>...</modules> block not found (or multiple unexpected blocks).")
    root_pom.write_text(patched, encoding="utf-8")
    print("✅ patched root pom.xml <modules> paths")


PARENT_BLOCK = re.compile(r"(<parent>\s*.*?</parent>)", re.DOTALL)


def patch_parent_relativepath(pom_path: Path) -> bool:
    """
    给 parent 是 (cn.iocoder.boot:future) 的子模块补 <relativePath>，否则目录移动后会找不到父 pom。
    已有 relativePath 则不重复写。
    """
    txt = pom_path.read_text(encoding="utf-8")

    m = PARENT_BLOCK.search(txt)
    if not m:
        return False

    block = m.group(1)

    # 只处理 parent 指向 root future 的模块
    if f"<groupId>{ROOT_GROUP_ID}</groupId>" not in block:
        return False
    if f"<artifactId>{ROOT_ARTIFACT_ID}</artifactId>" not in block:
        return False
    if "<relativePath>" in block:
        return False

    # 尽量跟随现有缩进风格
    indent_m = re.search(r"\n(\s*)<artifactId>", block)
    indent = indent_m.group(1) if indent_m else "        "

    rp = relpath_to_root(pom_path.parent)
    insert = f"\n{indent}<relativePath>{rp}</relativePath>"
    new_block = block.replace("</parent>", f"{insert}\n{indent}</parent>")

    new_txt = txt[:m.start(1)] + new_block + txt[m.end(1):]
    pom_path.write_text(new_txt, encoding="utf-8")
    return True


def write_aggregator_pom(pom_path: Path, artifact_id: str, modules: list[str]):
    """
    生成一个聚合 pom（packaging=pom），其 parent 指向 root future。
    modules 中的路径相对于该 pom 所在目录。
    """
    ensure_dir(pom_path.parent)
    rp = relpath_to_root(pom_path.parent)

    modules_xml = "\n".join([f"        <module>{m}</module>" for m in modules])

    content = f"""<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <parent>
        <groupId>{ROOT_GROUP_ID}</groupId>
        <artifactId>{ROOT_ARTIFACT_ID}</artifactId>
        <version>${{revision}}</version>
        <relativePath>{rp}</relativePath>
    </parent>

    <artifactId>{artifact_id}</artifactId>
    <packaging>pom</packaging>

    <modules>
{modules_xml}
    </modules>
</project>
"""
    pom_path.write_text(content, encoding="utf-8")
    print(f"✅ wrote aggregator pom: {pom_path}")


def move_custom_modules():
    """
    移动不在MOVE_PLAN中的future-module-xxx模块到modules/custom/xxx
    """
    custom_base = Path("modules/custom")
    custom_modules = []
    
    # 扫描当前目录下以"future-module-"开头的目录
    for item in Path(".").iterdir():
        if item.is_dir() and item.name.startswith("future-module-") and item.name not in MOVE_PLAN:
            # 从目录名中提取模块名（去掉"future-module-"前缀）
            module_name = item.name[len("future-module-"):]
            dst = custom_base / module_name
            move_dir(item, dst)
            custom_modules.append(module_name)
    
    return custom_modules


def main():
    if not ROOT_POM.exists():
        raise RuntimeError("❌ Run this script at repo root (pom.xml not found).")

    # 1) 移动预定义目录
    for s, d in MOVE_PLAN.items():
        move_dir(Path(s), Path(d))
    
    # 2) 移动自定义模块
    print("\n🔍 扫描并移动自定义模块...")
    custom_modules = move_custom_modules()
    if custom_modules:
        print(f"✅ 已移动 {len(custom_modules)} 个自定义模块到 modules/custom/")
    
    # 3) 先 patch root pom 的 modules，让 reactor 能找到新路径下的模块
    patch_root_modules(ROOT_POM)

    # 4) 生成你要的 modules/ 聚合层
    # 动态构建modules列表
    modules_list = ["core", "biz", "extend"]
    if custom_modules:  # 如果有自定义模块，就加入custom
        modules_list.append("custom")
    write_aggregator_pom(Path("modules/pom.xml"), "future-modules", modules_list)

    # core/biz/extend 聚合
    write_aggregator_pom(Path("modules/core/pom.xml"), "future-modules-core", ["system", "infra"])
    write_aggregator_pom(Path("modules/biz/pom.xml"), "future-modules-biz", ["crm", "erp", "mall"])

    extend_list = ["member", "bpm", "report", "mp", "pay", "ai"]
    if ENABLE_IOT_IN_AGGREGATOR:
        extend_list.append("iot")
    write_aggregator_pom(Path("modules/extend/pom.xml"), "future-modules-extend", extend_list)
    
    # 如果有自定义模块，生成custom聚合pom
    if custom_modules:
        write_aggregator_pom(Path("modules/custom/pom.xml"), "future-modules-custom", custom_modules)
        # 为每个自定义模块生成对应的聚合pom
        for module in custom_modules:
            # 自定义模块的目录名是去掉前缀后的名称
            module_dir_name = f"future-module-{module}"
            write_aggregator_pom(
                Path(f"modules/custom/{module}/pom.xml"), 
                f"future-custom-{module}", 
                [module_dir_name]
            )

    # 5) 每个域下面再放一个"目录级聚合 pom"，让结构更清晰
    # core
    write_aggregator_pom(Path("modules/core/system/pom.xml"), "future-core-system", ["future-module-system"])
    write_aggregator_pom(Path("modules/core/infra/pom.xml"), "future-core-infra", ["future-module-infra"])
    # biz
    write_aggregator_pom(Path("modules/biz/crm/pom.xml"), "future-biz-crm", ["future-module-crm"])
    write_aggregator_pom(Path("modules/biz/erp/pom.xml"), "future-biz-erp", ["future-module-erp"])
    write_aggregator_pom(Path("modules/biz/mall/pom.xml"), "future-biz-mall", ["future-module-mall"])
    # extend
    write_aggregator_pom(Path("modules/extend/member/pom.xml"), "future-ext-member", ["future-module-member"])
    write_aggregator_pom(Path("modules/extend/bpm/pom.xml"), "future-ext-bpm", ["future-module-bpm"])
    write_aggregator_pom(Path("modules/extend/report/pom.xml"), "future-ext-report", ["future-module-report"])
    write_aggregator_pom(Path("modules/extend/mp/pom.xml"), "future-ext-mp", ["future-module-mp"])
    write_aggregator_pom(Path("modules/extend/pay/pom.xml"), "future-ext-pay", ["future-module-pay"])
    write_aggregator_pom(Path("modules/extend/ai/pom.xml"), "future-ext-ai", ["future-module-ai"])
    if ENABLE_IOT_IN_AGGREGATOR:
        write_aggregator_pom(Path("modules/extend/iot/pom.xml"), "future-ext-iot", ["future-module-iot"])

    # 6) 给所有"父 POM=root future"的模块补 relativePath（移动后必须）
    changed = 0
    for pom in Path(".").rglob("pom.xml"):
        if pom.resolve() == ROOT_POM.resolve():
            continue
        try:
            if patch_parent_relativepath(pom):
                changed += 1
                print(f"✅ patched parent relativePath: {pom}")
        except Exception as e:
            raise RuntimeError(f"❌ failed to patch {pom}: {e}") from e

    print(f"🎉 done. patched parent relativePath count = {changed}")
    if custom_modules:
        print(f"📦 自定义模块 ({len(custom_modules)} 个): {', '.join(custom_modules)}")


if __name__ == "__main__":
    main()
