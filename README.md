# elfaudit — ELF 二进制安全审计器

仅使用 Python 标准库实现的 ELF 安全审计工具，无任何第三方依赖。

## 支持的 ELF 形态

| 维度 | 支持范围 |
| --- | --- |
| 类别 (`EI_CLASS`) | `ELFCLASS32`、`ELFCLASS64` |
| 字节序 (`EI_DATA`) | `ELFDATA2LSB`（小端）、`ELFDATA2MSB`（大端） |
| 文件类型 (`e_type`) | `ET_REL`、`ET_EXEC`、`ET_DYN`、`ET_CORE` 等 |
| 节区表 | 完整解析节区头，含扩展节区号 (`e_shnum=0`) 场景 |
| 程序头 | ELF32/ELF64 两种 `Phdr` 布局，含动态段解析 |
| 符号表 | `.dynsym`（`SHT_DYNSYM`）与 `.symtab`（`SHT_SYMTAB`） |
| 重定位 | `.rel`（`SHT_REL`）与 `.rela`（`SHT_RELA`） |

## 使用方式

```bash
python -m elfaudit.cli --target <elf 文件> --out <报告路径>
```

内置 demo：

```bash
python -m elfaudit.cli --target demo/sample.elf --out out/report.json
```

命令结束后 stdout 打印一行摘要，例如：

```
elfaudit: 5 check(s), 1 passed, 4 issue(s) reported
```

重新生成测试夹具（ELF32/ELF64、小端/大端均由通用构建器现场合成）：

```bash
python fixtures/generate_fixtures.py
```

运行测试：

```bash
python -m unittest test_elfaudit -v
```

## 解析能力

- **ELF 头**：magic、class、data、`e_type`、`e_machine`、`e_entry`、
  程序头表与节区头表的偏移和条目数。
- **节区**：通过节区头字符串表 (`.shstrtab`) 还原每个节区名，并读出
  `sh_type`、`sh_flags`、`sh_offset`、`sh_size`、`sh_addr`、`sh_link`、
  `sh_entsize` 等字段。
- **程序头**：读出 `p_type`（如 `PT_LOAD`、`PT_GNU_STACK`、
  `PT_INTERP`、`PT_GNU_RELRO`）、`p_flags`、`p_offset`、`p_vaddr`、
  `p_memsz`、`p_align`；`PT_DYNAMIC` 进一步解码为动态标签表，缺失
  程序头时回退到 `SHT_DYNAMIC` 节区。
- **符号表**：对 `.dynsym` 与 `.symtab` 逐条解析 `st_name`、`st_info`、
  `st_shndx`、`st_value`、`st_size`，并从关联字符串表还原符号名；
  `st_shndx == SHN_UNDEF` 且具名的符号识别为导入符号。
- **重定位**：解析 `.rel` / `.rela` 条目的 `r_offset`、`r_info`、
  `r_addend`（`.rel` 无附加数，置 0），并从 `r_info` 拆出符号索引与
  重定位类型。

## 检查项与判定依据

每个检查项在 JSON 报告中都包含且仅包含 `name`、`passed`、`detail`
三个字段，`detail` 始终带可核对的证据。

| name | 判定为问题 (`passed=false`) 的条件 | 证据 |
| --- | --- | --- |
| `nx` | 存在 `PT_GNU_STACK` 且其 `p_flags` 含 `PF_X`（0x1） | 写出 `PT_GNU_STACK` 的 flags 数值、十六进制值与 `RWX` 形式 |
| `pie` | `e_type != ET_DYN`（如 `ET_EXEC` 不可按 PIE 加载） | 写出 `e_type` 数值与符号名 |
| `relro` | 存在 `PT_GNU_RELRO`，但动态段既无 `DT_BIND_NOW`，也无携带 `DF_1_NOW` 的 `DT_FLAGS_1`；或直接缺少 `PT_GNU_RELRO` | 写出缺失的标签名（`DT_BIND_NOW`、`DT_FLAGS_1/DF_1_NOW`）或缺失的段 |
| `dangerous_symbols` | `.dynsym` 的导入符号中出现 `strcpy`、`system`、`execve`、`gets` | 写出命中的符号名 |
| `not_stripped` | `.symtab` 存在且条目数不为 0 | 写出 `.symtab` 的类型、条目数、偏移与大小 |

说明：

- 没有 `PT_GNU_STACK` 时按现代加载器默认行为视为不可执行栈，`nx` 通过。
- 完整 RELRO 需要“只读重定位区域 (`PT_GNU_RELRO`) + 立即绑定
  (`DT_BIND_NOW` 或 `DF_1_NOW`)”同时成立；只有 `PT_GNU_RELRO` 而没有
  立即绑定标记时判为 RELRO 不完整。
- 危险符号只统计导入（未定义、需动态链接器解析）的具名符号，避免把
  本二进制内自定义的同名函数误报为导入风险。

## 报告结构

```json
{
  "target": "demo/sample.elf",
  "elf": { "class": "ELF64", "data": "little", "...": "..." },
  "summary": { "total_checks": 5, "passed": 1, "failed": 4 },
  "checks": [
    { "name": "nx", "passed": false, "detail": "...证据..." }
  ]
}
```

## 目录结构

```
elfaudit/            审计器包
  elf_header.py      ELF 头解析（32/64 位、双字节序）
  sections.py        节区头与节名字符串表
  segments.py        程序头与动态段
  symbols.py         .dynsym / .symtab 解析
  relocs.py          .rel / .rela 重定位解析
  checks.py          五项安全检查
  report.py          审计编排与 JSON 报告
  cli.py / __main__.py  命令行入口
fixtures/            通用 ELF 构建器、夹具生成脚本与合成 ELF
tests/test_elfaudit.py  unittest 测试（覆盖全部判定口径）
demo/sample.elf      demo 输入
```
