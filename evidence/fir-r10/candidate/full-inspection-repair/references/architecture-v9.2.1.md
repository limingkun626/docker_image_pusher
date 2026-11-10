# 一次性检查与修复系统 V9.2.1 架构方案

文档状态：独立架构基线  
版本：V9.2.1  
Skill 包版本：`1.4.0`  
修订日期：2026-11-10  
适用范围：技能、方案、文章、项目及其他可检查对象  
目标：全仓普查、全局影响分析、一次批量修复、全量验证、零开放风险关闭

## 1. 方案定位

V9.2.1 不是任何旧版本的补丁合集，而是一份重新组织的完整基线。它把“检查”和
“修复”设计成一个证据驱动的单向闭环，不依赖不断试错来发现问题。

系统必须回答五个问题：

1. 被检查对象由哪些资源、声明、行为和外部依赖组成？
2. 应检查的缺陷类别、证据平面和异常路径是否全部进入分母？
3. 每个已发现问题是否影响其他模块、契约、测试、部署或发布声明？
4. 所有问题能否形成一个无冲突、可回滚、一次应用的修复批次？
5. 修复后的候选是否通过同一冻结范围内的全量验证，并达到零开放风险？

系统不能承诺“证明未知世界中不存在任何缺陷”。系统承诺的是：

```text
对冻结对象全集、已登记缺陷类别、适用证据平面和已声明外部依赖，
所有已发现问题逐项登记、逐项影响分析、逐项修复或证明为假阳性，
全部由当前候选上的可验证证据关闭，最终开放风险为零。
```

任何无法执行、无法验证、无法授权或无法确认的内容都必须成为开放项并阻断完成。
不允许降级为“低风险”“非阻塞”“后续处理”或默认 backlog。

## 2. 设计原则

### 2.1 同一标准

技能、方案、文章、项目和扩展对象类型使用同一套问题模型、严重程度词表、
风险账本、修复事务、验证矩阵和完成公式。目标适配器只负责枚举对象资源和
映射检查能力，不得定义更宽松的完成条件。

### 2.2 先穷尽，后修复

发现阶段采用 `collect-all`：检测器失败只记录该检查项的失败状态，不提前终止
其他检测器。只有冻结问题全集和影响图形成后，才允许生成修复计划。

### 2.3 严重程度只排序

`Critical / High / Medium / Low` 只决定处理顺序和资源权重。任何严重程度的问题
都必须进入问题账本；任何未闭合项都阻断最终完成。

### 2.4 一次批量修复

所有已确认问题由同一冻结计划、同一冲突图、同一候选树和同一验证矩阵处理。
禁止边修边查、逐个问题提交、局部测试后继续发现、再把上一轮遗漏转入下一轮。

### 2.5 证据先于结论

每个关闭项必须绑定当前对象版本、当前策略版本、可重放证据、证据摘要和验证检查。
汇总状态不能替代底层问题，单个测试通过也不能替代全量覆盖。

### 2.6 单次闭环，无自动回流

一次运行只允许：

```text
完整发现 -> 完整规划 -> 一次候选 -> 全量验证 -> 关闭或 BLOCKED
```

`FULL_VERIFICATION` 没有回到 `ISSUE_DISCOVERY`、`BATCH_PLANNED` 或
`CANDIDATE_BUILT` 的自动边。验证失败时整批作废并立即 `BLOCKED`，不允许
系统自动再发现、再修复、再验证。后续若要继续，必须由用户显式发起新的
scope generation，并重新冻结完整问题全集。

输入、环境、配置、工具或 adapter digest 在当前运行中发生变化时，本次运行
立即进入 `BLOCKED_STALE_INPUT`。不得自动回到 `SCOPE_FROZEN`，不得自动重跑
census 或修复。只有用户显式发起新的 `scope_id`，才能重新冻结输入。

### 2.7 运行与学习双时钟

检查运行和学习更新是两个隔离时钟：

```text
Inspection Clock
  frozen knowledge pack
  -> census / detect / repair / verify / close
  -> immutable run evidence

Learning Clock
  run evidence + incidents
  -> issue knowledge extraction
  -> detector candidate
  -> train / validation / held-out replay
  -> independent promotion
  -> next knowledge pack
```

当前运行只能读取冻结的 knowledge pack，不能在运行中激活新 detector 或修改
已有知识。当前运行发现的新问题只能写入 observation journal，并立即影响本次
风险账本；其知识化和 detector 升级发生在运行结束后，只能用于下一次显式运行。

知识库可以提高未来一次通过全量验证的概率，但不能把有限检测器和有限 oracle
变成完备证明。新交互、新环境、新输入、未知缺陷类别和验证器盲区仍然可能在
第一次候选上暴露。V9.2.1 保证的是失败不会触发自动回流，而不是保证首轮必过。

knowledge pack 必须整体发布，不允许把单个 candidate 直接插入 active set。
新 pack 先在当前 active pack、历史 regression corpus 和独立 held-out 上做
shadow replay；只有检测能力不退化、误报不越界、成本不超限时才能原子替换
旧 pack。失败 pack 保留完整证据但不得进入下一次运行。

## 3. 总体架构

```text
                         ┌──────────────────────────┐
                         │ Control Plane            │
                         │ scope / policy / state   │
                         │ budget / identity / ACL  │
                         └────────────┬─────────────┘
                                      │
        ┌─────────────────────────────┼─────────────────────────────┐
        │                             │                             │
┌───────▼────────┐          ┌─────────▼─────────┐         ┌─────────▼─────────┐
│ Target Adapter │          │ Inspection Plane  │         │ Evidence & Closure│
│ skill / plan   │          │ census / detectors│         │ ledger / reports  │
│ article/project│          │ oracles / matrices│         │ digests / review  │
└───────┬────────┘          └─────────┬─────────┘         └─────────┬─────────┘
        │                             │                             │
        │                    ┌────────▼─────────┐                   │
        │                    │ Knowledge Plane  │                   │
        │                    │ issue history    │                   │
        │                    │ detector learning│                   │
        │                    └────────┬─────────┘                   │
        │                             │ frozen pack only             │
        └──────────────┬──────────────┴──────────────┬──────────────┘
                       │                             │
              ┌────────▼────────┐           ┌────────▼────────┐
              │ Impact & Repair │           │ Verification    │
              │ graph / planner │           │ full matrix     │
              │ transaction     │           │ independent gate│
              └─────────────────┘           └─────────────────┘
```

### 3.1 Control Plane

负责：

- 冻结范围、对象身份和策略版本；
- 维护无自动回流状态机和显式新运行规则；
- 管理预算、并发、超时和失败隔离；
- 校验权限、副作用边界和目标可用性；
- 生成每个阶段的 canonical digest。

不负责具体对象解析、缺陷判断或修复策略。

### 3.2 Target Adapter Plane

每种对象类型实现一个 `target adapter`：

- 技能适配器解析 `SKILL.md`、references、scripts、agents 元数据、安装与发现；
- 方案/文章适配器解析章节、引用、声明、图表、代码块、链接和外部来源；
- 项目适配器解析源码、依赖、构建、测试、CI、部署、配置和发布链。

统一接口：

<!-- documented-json: non-contract-example -->

```json
{
  "adapter_id": "target.skill",
  "adapter_version": "1.0.0",
  "target_kinds": ["SKILL"],
  "build_manifest": "returns resource and claim inventory",
  "build_graph": "returns dependency and impact edges",
  "detector_bindings": "maps invariant to detector packs",
  "repair_bindings": "maps defect classes to safe patches",
  "verification_bindings": "maps checks to executable oracles",
  "lifecycle_bindings": "declares install, run, uninstall and read-back",
  "unsupported_capabilities": "returns explicit blocking gaps"
}
```

适配器不得自行宣布 `PASS`，也不得修改公共风险状态。

### 3.3 Inspection Plane

包含四类检查：

1. `Resource Census`：文件、符号、章节、链接、配置、依赖、数据库、外部服务。
2. `Contract Check`：schema、接口、命名、引用、权限、状态、配置和发布合同。
3. `Semantic Check`：调用链、数据流、影响链、内容一致性、章节完整性。
4. `Behavior Check`：触发、指令遵循、任务结果、动态执行、性能和安全行为。

每个检查器必须声明：

```text
detector_id, detector_version, applicable_target_kinds,
invariant_ids, evidence_plane, required_inputs, oracle_ids,
known_false_negatives, cost_profile, timeout, failure_mode
```

### 3.4 Impact & Repair Plane

将 finding 映射到：

- 受影响资源；
- 受影响接口和调用者；
- 受影响测试和 oracle；
- 受影响文档、配置、部署和发布声明；
- 修复冲突与回滚边界；
- 必须重新运行的最小充分验证集合。

修复执行使用事务化候选树，不允许直接修改生产对象。

### 3.5 Verification Plane

使用冻结验证矩阵一次性覆盖：

- 静态、类型、schema 和接口；
- 单元、集成、端到端；
- 属性测试、变异测试、模糊测试和负向测试；
- held-out 行为评测；
- 跨平台和运行时；
- 安全、权限、秘密、依赖和供应链；
- 性能、资源、超时和恢复；
- 安装、卸载、升级、回滚和外部引用清理。

### 3.6 Evidence & Closure Plane

保存所有输入摘要、检测结果、影响边、修复计划、候选摘要、验证回执和独立裁决。
最终结论只由证据链计算，不允许人工手写一个 `PASS` 覆盖失败证据。

### 3.7 Knowledge Plane

该平面不在当前检查运行的写路径上。它维护：

- issue observations；
- 缺陷模式、根因模式和适用边界；
- detector candidate 与 regression cases；
- learned helpful/harmful counters；
- knowledge pack 版本、摘要、晋升和被替代关系。

当前运行只能读取一个冻结的 `knowledge_pack_digest`。运行结束后，新 observation
才能进入学习流程；学习结果不能改写已经结束的候选或验证证据。

## 4. 核心数据模型

本节 JSON 代码块是便于阅读的结构示例，不是可直接提交的合同载荷：其中
`"string"`、`"sha256"` 和枚举连写只表达语义。可执行合同以
`contracts/*.schema.json` 为准；文档契约测试要求每个 JSON 块显式标记为
`non-contract-example`，防止把示例误当成完整 payload。

### 4.1 Subject Manifest

<!-- documented-json: non-contract-example -->

```json
{
  "schema_version": 2,
  "subject_id": "string",
  "subject_kind": "SKILL|PLAN|ARTICLE|PROJECT|OTHER",
  "subject_root": "absolute path or immutable URI",
  "adapter_id": "string",
  "adapter_version": "string",
  "adapter_contract_digest": "sha256",
  "knowledge_pack_id": "string",
  "knowledge_pack_digest": "sha256",
  "detector_pack_digest": "sha256",
  "defect_taxonomy_digest": "sha256",
  "taxonomy_coverage_digest": "sha256",
  "fingerprint_registry_digest": "sha256",
  "evidence_policy_digest": "sha256",
  "tree_digest": "sha256",
  "config_digest": "sha256",
  "generation": 1,
  "snapshot_digest": "sha256",
  "root_generation": "sha256",
  "directories": ["skill-root"],
  "files": ["file metadata objects"],
  "character_coverage_digest": "sha256",
  "codepoint_count": 0,
  "punctuation_count": 0,
  "uncovered_character_count": 0,
  "coverage_gap_count": 0
}
```

### 4.2 Required Source

<!-- documented-json: non-contract-example -->

```json
{
  "schema_version": 1,
  "source_id": "stable id",
  "source_type": "RESOURCE|CLAIM|INVARIANT|PLANE|BEHAVIOR|RUNTIME|LIFECYCLE|EXTERNAL",
  "locator": "file/path/symbol/section/row id",
  "applicability": "APPLICABLE|NOT_APPLICABLE_WITH_PROOF",
  "proof_ref": null
}
```

`required_sources` 是本次检查的完整分母。分母本身必须写入 scope digest。

### 4.3 Finding / Risk Entry

<!-- documented-json: non-contract-example -->

```json
{
  "schema_version": 1,
  "risk_id": "sha256-derived stable id",
  "invariant_id": "string",
  "defect_class_id": "string",
  "taxonomy_category_id": "string",
  "subject_id": "string",
  "source_id": "string",
  "severity": "Critical|High|Medium|Low",
  "message": "specific observable failure",
  "mechanism": "why it occurs",
  "affected_refs": ["path or symbol"],
  "root_cause_id": "string",
  "status": "OPEN|FIXED|FALSE_POSITIVE_WITH_PROOF|PREVENTED_BY_VERIFIED_GUARD|SUPERSEDED_BY_VERIFIED_CHANGE",
  "evidence_refs": ["current receipts"],
  "evidence_sha256": "sha256",
  "closed_by": "string",
  "closed_at": "RFC3339 timestamp",
  "verification_check": "command or receipt id",
  "residual_risk": null
}
```

一项 finding 只对应一个具体失败机制。多个机制不得合并成一个模糊条目。

### 4.4 Root Cause

<!-- documented-json: non-contract-example -->

```json
{
  "root_id": "sha256(invariant, normalized_cause, primary_surfaces)",
  "invariant_id": "string",
  "defect_class_id": "string",
  "normalized_cause": "string",
  "finding_ids": ["..."],
  "primary_surfaces": ["path or symbol"],
  "analogous_surfaces": ["path, section, symbol or project"],
  "shared_dependencies": ["..."],
  "repair_dependencies": ["root ids"],
  "closure_rule": "all descendant findings closed or independently proven superseded",
  "counterexamples": ["..."],
  "status": "OPEN|CLOSED|BLOCKED"
}
```

一个 root 可以关联多个 finding，但每个 finding 必须有唯一 root lineage；关闭 root
必须同时证明其所有 finding、analogous surfaces 和 downstream consumers 已闭合。
修复一个症状不能自动关闭共享根因，除非有反例、影响图和回归证据。

### 4.5 Risk Ledger

<!-- documented-json: non-contract-example -->

```json
{
  "schema_version": 1,
  "scope_digest": "sha256",
  "finding_schema_digest": "sha256",
  "risk_ledger_schema_digest": "sha256",
  "required_sources": ["..."],
  "required_sources_digest": "sha256",
  "observed_sources": ["..."],
  "items": ["RiskEntry"],
  "open_count": 0,
  "closed_count": 0,
  "missing_sources": [],
  "unexpected_sources": [],
  "residual_risks": [],
  "unresolved_ids": [],
  "ledger_digest": "sha256"
}
```

### 4.6 Issue Observation

每次检查或验证发现的新问题先进入 append-only observation journal：

<!-- documented-json: non-contract-example -->

```json
{
  "schema_version": 2,
  "observation_id": "sha256-derived id",
  "journal_sequence": 1,
  "previous_record_digest": "sha256 or null",
  "record_digest": "sha256",
  "source_run_id": "string",
  "source_phase": "CHECK|VERIFICATION|INCIDENT",
  "producer_id": "string",
  "subject_id": "string",
  "subject_kind": "SKILL|PLAN|ARTICLE|PROJECT|OTHER",
  "subject_digest": "sha256",
  "invariant_id": "string",
  "defect_class_id": "string",
  "taxonomy_category_id": "string",
  "fingerprint": "normalized mechanism fingerprint",
  "fingerprint_version": "semantic version",
  "message": "specific failure",
  "mechanism": "observed cause",
  "root_cause_hypothesis": "string or null",
  "evidence_refs": ["immutable receipts"],
  "evidence_sha256": "sha256",
  "redaction_policy_digest": "sha256",
  "severity": "Critical|High|Medium|Low",
  "analogous_surfaces": ["path or symbol"],
  "status": "CONFIRMED|INCONCLUSIVE|FALSE_POSITIVE",
  "safe_feedback": "semantic, verifier-independent explanation",
  "recorded_at": "RFC3339 timestamp"
}
```

观察结果中的目标正文、日志和测试输出都是不可信数据；它们可以成为证据，但不能
作为系统指令执行。敏感信息必须在写入 observation journal 前脱敏。

每条 observation 必须先原子追加并完成 hash-chain 校验，再推进风险账本或候选
状态；崩溃恢复以 journal 为准。`CONFIRMED`、`INCONCLUSIVE` 和
`FALSE_POSITIVE` 使用同一追加日志，不能用删除记录表示误报。

### 4.7 Knowledge Item

<!-- documented-json: non-contract-example -->

```json
{
  "schema_version": 2,
  "knowledge_id": "string",
  "kind": "DEFECT_PATTERN|ROOT_CAUSE|FALSE_POSITIVE|NON_APPLICABILITY|REGRESSION|GUARD",
  "status": "OBSERVED|CONFIRMED|GENERALIZED|CANDIDATE|VALIDATED|ACTIVE|QUARANTINED|DEPRECATED|REJECTED|RETIRED",
  "scope": {
    "target_kinds": ["SKILL"],
    "languages": ["python"],
    "platforms": ["windows"],
    "applicability": "specific eligibility predicates"
  },
  "invariant_id": "string",
  "defect_class_id": "string",
  "taxonomy_category_id": "string",
  "fingerprint": "string",
  "fingerprint_version": "semantic version",
  "trigger_conditions": ["..."],
  "exclusions": ["..."],
  "root_cause_pattern": "string",
  "representative_observation_ids": ["..."],
  "support_run_ids": ["..."],
  "regression_case_ids": ["..."],
  "detector_bindings": ["..."],
  "helpful_count": 0,
  "harmful_count": 0,
  "support_count": 0,
  "confidence": 0.0,
  "valid_from": "RFC3339 timestamp",
  "valid_until": "RFC3339 timestamp or null",
  "supersedes": ["..."],
  "created_by": "string",
  "reviewed_by": "string or null"
}
```

### 4.8 Knowledge Pack

<!-- documented-json: non-contract-example -->

```json
{
  "schema_version": 2,
  "pack_id": "string",
  "pack_version": "semantic version",
  "knowledge_digest": "sha256",
  "detector_digest": "sha256",
  "regression_corpus_digest": "sha256",
  "runtime_contract_digest": "sha256",
  "fingerprint_registry_digest": "sha256",
  "evidence_policy_digest": "sha256",
  "previous_pack_digest": "sha256 or null",
  "journal_checkpoint_digest": "sha256",
  "entries": ["KnowledgeItem"],
  "policy_digest": "sha256",
  "created_at": "RFC3339 timestamp",
  "expires_at": "RFC3339 timestamp or null",
  "approved_by": "independent-knowledge-reviewer"
}
```

每次检查只读取一个已批准 pack。pack 变化后，旧运行结果保持有效，但不能把新
detector 补进旧 scope。

### 4.9 Learning Candidate

<!-- documented-json: non-contract-example -->

```json
{
  "schema_version": 2,
  "candidate_id": "string",
  "derived_from_observation_ids": ["..."],
  "candidate_type": "DETECTOR|GUARD|REGRESSION|NON_APPLICABILITY",
  "pattern": "machine-readable rule or generalized predicate",
  "fingerprint_version": "semantic version",
  "train_case_ids": ["..."],
  "validation_case_ids": ["..."],
  "held_out_case_ids": ["..."],
  "metrics": {
    "precision": 0.0,
    "recall": 0.0,
    "false_positive_rate": 0.0,
    "mutation_kill_rate": 0.0,
    "historical_replay_misses": 0
  },
  "status": "CANDIDATE|VALIDATED|QUARANTINED|REJECTED|ACTIVE",
  "review_receipt": "signed review",
  "activated_in_pack": null
}
```

### 4.10 Repair Batch

<!-- documented-json: non-contract-example -->

```json
{
  "batch_id": "string",
  "base_subject_digest": "sha256",
  "issue_set_digest": "sha256",
  "root_ids": [],
  "root_dag": [],
  "finding_root_map": {},
  "operations": [],
  "conflict_graph": [],
  "preimages": [],
  "postimages": [],
  "rollback_plan": [],
  "candidate_digest": "sha256",
  "candidate_generation": 1
}
```

同一次 V9.2.1 运行中 `candidate_generation` 恒为 `1`。新的用户授权运行必须使用新的
`scope_id`，不能把新候选伪装成当前运行的第二次 generation。

### 4.11 Defect Taxonomy Coverage

“所有缺陷类别”不能只存在于文字说明。每次运行必须从同一个版本化 taxonomy
生成目标类型、缺陷类别、证据平面的覆盖矩阵：

<!-- documented-json: non-contract-example -->

```json
{
  "schema_version": 1,
  "taxonomy_id": "inspection-closure.defect-taxonomy",
  "taxonomy_version": "semantic version",
  "categories": [
    "FUNCTIONAL_FAULT",
    "RISK_EXPOSURE",
    "LATENT_DEFECT",
    "VULNERABILITY",
    "OMISSION",
    "INCONSISTENCY",
    "BOUNDARY",
    "EXCEPTION_PATH",
    "OTHER_DECLARED"
  ],
  "target_kinds": ["SKILL", "PLAN", "ARTICLE", "PROJECT", "OTHER"],
  "evidence_planes": [
    "STATIC",
    "CONTRACT",
    "SEMANTIC",
    "BEHAVIOR",
    "RUNTIME",
    "SECURITY",
    "PERFORMANCE",
    "LIFECYCLE"
  ],
  "cells": [
    {
      "target_kind": "SKILL",
      "category_id": "OMISSION",
      "evidence_plane": "STATIC",
      "detector_ids": ["..."],
      "oracle_ids": ["..."],
      "not_applicable_proof": null,
      "status": "COVERED|UNCOVERED|BLOCKED"
    }
  ],
  "coverage_digest": "sha256"
}
```

规则：

- 每个 required target kind × defect category × evidence plane 单元都必须有
  detector、独立 oracle 或经过证据证明的 `NOT_APPLICABLE`；
- detector、oracle 和 proof 同时缺失的单元是 `UNCOVERED`，结果只能是
  `BLOCKED_TAXONOMY`；
- 每个 finding 必须绑定一个 taxonomy category；未知类别不能被归入“其他”并
  静默放行，必须先登记类别并重新冻结 scope；
- 新增 target kind、adapter 或 defect category 时，所有未映射单元自动成为
  阻断项，不能继承旧版本的隐含 `NOT_APPLICABLE`；
- taxonomy registry、覆盖矩阵和 coverage digest 进入 Scope Lock。

## 5. 状态机

```text
INTAKE
  -> SCOPE_FROZEN
  -> SUBJECT_CENSUS
  -> ISSUE_DISCOVERY
  -> IMPACT_CLOSURE
  -> BATCH_PLANNED
  -> PREFLIGHT_VERIFIED
  -> CANDIDATE_BUILT
  -> FULL_VERIFICATION
  -> INDEPENDENT_REVIEW
  -> CLOSED_FOR_DECLARED_UNIVERSE
```

失败状态：

```text
BLOCKED_SCOPE
BLOCKED_ADAPTER
BLOCKED_TAXONOMY
BLOCKED_STALE_INPUT
BLOCKED_DETECTOR
BLOCKED_EVIDENCE
BLOCKED_REPAIR_PLAN
BLOCKED_REPAIR_CONFLICT
BLOCKED_VERIFICATION
BLOCKED_INDEPENDENT_REVIEW
```

规则：

- 输入 digest 变化后，所有下游证据失效并进入 `BLOCKED_STALE_INPUT`；不得自动回到 `SCOPE_FROZEN`。
- taxonomy 存在未覆盖单元时进入 `BLOCKED_TAXONOMY`，不得继续检测。
- 发现器失败不能跳过检查项，必须以 `BLOCKED_DETECTOR` 留在分母中。
- 修复批次冻结前必须通过 preflight；preflight 失败时不生成候选。
- 修复批次冻结后不得逐项偷改。
- `FULL_VERIFICATION` 失败只通向 `BLOCKED_VERIFICATION`，不得自动回到发现或规划。
- 新 root 或新 target kind 出现时，属于新的 scope generation，不属于当前批次。

Learning Clock 使用独立状态机：

```text
OBSERVING
  -> TRIAGED
  -> GENERALIZED
  -> CANDIDATE
  -> REPLAYING
  -> VALIDATED
  -> PACK_PUBLISHED
  -> ACTIVE
```

任一阶段可进入 `REJECTED`。`ACTIVE` 可转为 `DEPRECATED` 或 `RETIRED`。
Learning Clock 不拥有修改当前 candidate 或当前 risk ledger 状态的能力。

## 6. 一次性执行流程

### 阶段 1：Scope Lock

生成并冻结：

- subject manifest；
- target adapter 版本；
- active knowledge pack 及其 digest；
- detector pack、regression corpus 和 knowledge policy digest；
- defect taxonomy registry 和 taxonomy coverage matrix；
- invariant/defect registry；
- detector/repair/verification registry；
- 外部依赖和不可逆操作白名单；
- 固定覆盖配额、成本上限和超时；
- 所有 target kind 的适用性证明。

完成条件：所有输入均有 digest，knowledge pack 的 scope 与当前 target kinds 匹配，
taxonomy coverage 没有未覆盖单元，且没有未声明的适用对象类型。运行中不得重新
解析或热更新 knowledge pack、taxonomy 或 detector pack。

### 阶段 2：Total Census

枚举全部 resources 和 claims：

- 文件、符号、章节、链接、脚本、测试、配置、依赖和外部服务；
- 声明支持的平台、运行时、接口、能力、权限和发布边界；
- 生成、缓存、安装、升级、回滚和清理路径；
- 静态不可见但可动态发现的插件、钩子、任务和自动化。

每个 source 必须进入 `required_sources`，不能以未知文件类型静默跳过。

### 阶段 3：Collect-All Detection

先验证 detector bindings 覆盖 taxonomy matrix 的全部 required cells，再并行运行
所有适用 detector packs。任何单个 detector 失败：

- 记录 failure receipt；
- 标记对应 invariant `UNCOVERED/BLOCKED`；
- 继续完成其他 detector；
- 不允许把失败解释为 `PASS` 或 `NOT_APPLICABLE`。

此时输出完整 issue set，不开始局部修复。

### 阶段 4：Global Impact Closure

对每个 issue 计算：

- 直接资源影响；
- 调用链和数据流影响；
- 接口和契约影响；
- 测试、oracle、fixture 影响；
- 文档、配置、部署和发布声明影响；
- 跨语言、跨模块、跨外部系统影响。

影响图必须覆盖真实影响边和 `NO_IMPACT` 证明。不能因为图太大就删除边。

影响闭包后执行 root clustering：

- 用 invariant、标准化 cause 和 primary surface 生成稳定 `root_id`；
- 所有 finding 必须映射到一个 root 或明确的独立 singleton root；
- 共享根因保留全部子 finding，不允许只保留一个代表项；
- 一个 root 的修复只有在所有子 finding、analogous surface 和 downstream
  consumer 均有闭合证据时才能关闭；
- root map 和 root DAG 进入 frozen batch，不允许在修复中临时新增未登记 root。

### 阶段 5：Single Batch Plan

把所有已确认问题合并为一个计划：

- 共享文件写入必须形成冲突图；
- 每个 operation 绑定 finding、preimage、postimage 和回滚策略；
- 自动修复只用于语义闭合、可验证且可逆的 defect class；
- 无法自动修复的问题仍进入同一批次，状态为阻塞，不转成 backlog；
- 计划冻结后生成 `batch_digest`。

### 阶段 5.5：Plan Preflight

在生成候选前一次性验证计划本身：

- 每个 operation 的 preimage 与当前冻结输入一致；
- 共享路径、依赖顺序和生成物写入没有未解决冲突；
- 每个修复都绑定 invariant、finding、oracle 和回滚动作；
- 所有 required verification cells 都有可执行 runner；
- 目标环境、权限、工具版本和外部依赖均满足；
- dry-run 后的全量计划能够通过 schema 和完整性检查；
- 计划不会修改受保护证据、验证器或不可写对象。

Preflight 失败时不生成候选。该失败是 `BLOCKED_REPAIR_PLAN`，不是自动开始第二轮检查。

### 阶段 6：Candidate Build

在隔离目录构建候选：

- 不允许直接修改生产对象；
- 每个变更都有 preimage/postimage digest；
- 应用失败则整批回滚；
- 同内容替换、symlink、路径大小写、删除和跨卷操作必须单独验证；
- 生成不可变 candidate manifest。

### 阶段 7：Full Verification

一次性运行冻结矩阵：

```text
contract + static
+ unit + integration + end-to-end
+ property + mutation + fuzz
+ negative controls
+ held-out behavior
+ task outcome + instruction following
+ security + permission + secret + supply chain
+ runtime matrix
+ lifecycle cleanup
+ performance and recovery
```

验证必须绑定：

```text
base_subject_digest, candidate_digest, issue_set_digest,
batch_digest, policy_digest, environment_digest,
oracle_digest, evaluator_digest
```

任何缺失 plane 都保持开放，不得用另一层证据替代。

验证中发现的新失败也必须：

1. 先生成新的 finding/risk entry；
2. 原子追加 `observations.jsonl` 并校验 hash chain；
3. 保留失败 trace 和最小复现；
4. 将当前 candidate 置为 `BLOCKED_VERIFICATION`；
5. 不触发当前运行的自动再修复。

第 2 步必须先于第 4 步完成。若 observation 写入失败，本次运行以
`BLOCKED_EVIDENCE` 结束，不能只留下状态而丢失问题知识。

### 阶段 8：Zero Open Risk Closure

最终通过条件：

```text
required_sources complete
∧ every source has terminal proof
∧ open_count == 0
∧ missing_sources == []
∧ unexpected_sources == []
∧ residual_risks == []
∧ all closure evidence belongs to the current candidate digest
∧ impact graph has no unresolved frontier
∧ verification matrix has no skipped required cell
∧ independent reviewer identity differs from producer
∧ release claim scope <= verified scope
```

### 阶段 9：Independent Review

非生产者评审必须：

- 重算 scope、knowledge pack、issue、batch、candidate、verification 和 ledger digests；
- 抽查所有关闭证据；
- 运行负向控制；
- 检查是否存在 INFO、accepted、deferred、residual 或合并隐藏；
- 给出 `RELEASE_READY` 或 `BLOCKED`。

独立评审不得修改候选。评审提出的任何问题都进入同一风险账本。

### 阶段 10：离线知识沉淀（不属于当前运行）

当前运行关闭或阻塞后，才允许启动 Learning Clock：

1. 从 risk ledger、verification failures 和 incidents 提取 observation。
2. 对 observation 做脱敏、归一化、去重和 root-cause 聚类。
3. 检索历史同类问题，生成 trigger、exclusion、scope 和 analogous surfaces。
4. 生成 detector、guard、regression case 或 non-applicability candidate。
5. 在 train / validation / held-out 三类历史案例上回放。
6. 通过精度、召回、假阳性、mutation 和资源预算门禁。
7. 由非 producer reviewer 批准后进入新的 knowledge pack。
8. 下一次显式检查只读取新的 frozen knowledge pack。

验证阶段发现的新问题必须写入 observation journal 和本次 risk ledger，但当前
candidate 仍然 `BLOCKED_VERIFICATION`。学习流程不能回头修改当前候选，也不能
把新 detector 注入已经冻结的运行。

## 7. 全仓检查矩阵

### 7.1 技能

| 平面 | 必检内容 |
|---|---|
| 结构 | SKILL.md、frontmatter、命名、references、scripts、agents、assets、tests |
| 引用 | 链接可达性、路径逃逸、循环、孤儿资源、渐进披露 |
| 脚本 | CLI 清单、参数、退出码、超时、路径、编码、无效输入 |
| 权限 | 文件、网络、进程、环境变量、凭据和高风险副作用 |
| 行为 | 正/负触发、with/without arm、held-out、任务结果、指令遵循 |
| Catalog | 名称、别名、描述、保护任务、加载顺序和近邻干扰 |
| 生命周期 | 安装、发现、升级、卸载、回滚、缓存、任务和外部引用 |
| 运行时 | OS、shell、Python/Node 版本、编码、路径语义和工具版本 |

### 7.2 方案

| 平面 | 必检内容 |
|---|---|
| 目标 | 目标、范围、约束、假设和验收标准是否闭环 |
| 结构 | 章节、依赖关系、术语、输入输出和状态转换 |
| 一致性 | 前后矛盾、重复定义、失效引用、版本冲突 |
| 完整性 | 失败路径、回滚、安全、性能、测试和发布 |
| 可行性 | 依赖、预算、人员、环境和外部协调 |
| 证据 | 数据、引用、计算、案例和结论是否可追溯 |

### 7.3 文章

| 平面 | 必检内容 |
|---|---|
| 事实 | 断言、数字、引用、链接和来源时间 |
| 结构 | 论点、证据、章节、段落和结论的一致性 |
| 语言 | 歧义、夸大、逻辑跳跃、重复和术语漂移 |
| 合规 | 版权、隐私、敏感数据、许可证和平台政策 |
| 可用性 | 格式、引用可读性、可访问性和目标读者匹配 |

### 7.4 项目

| 平面 | 必检内容 |
|---|---|
| 代码 | 语法、类型、调用链、数据流、错误处理和边界 |
| 依赖 | 版本、锁定、许可证、供应链、漏洞和弃用 |
| 测试 | 覆盖、断言质量、负向、属性、变异和 flaky |
| 构建 | 可重复构建、环境、生成物、缓存和发布包 |
| 运行 | 配置、迁移、可观测性、容量、恢复和兼容 |
| 发布 | 版本、身份、签名、回滚、安装和文档 |

### 7.5 评测结果语义

行为、benchmark 和 held-out 结果必须区分：

```text
PASS | FAIL | TIMEOUT | INFRA_ERROR | UNSCORED | MISSING
```

- `TIMEOUT`、`INFRA_ERROR`、`UNSCORED` 和 `MISSING` 都不能冒充真实 `FAIL`，
  也不能冒充 `PASS`；
- 每个 requested case 必须出现在最终对账中；重试集合由已落盘结果计算，包含
  失败和从未产生结果的 case；
- `UNSCORED` 可以从统计指标分母排除，但不能从覆盖账本和完成分母消失；
- 全部 requested case 均 `UNSCORED`、超时或基础设施失败时，结论是
  `INCONCLUSIVE/BLOCKED`，不是 0 分，也不是满分；
- FAIL_TO_PASS 与 PASS_TO_PASS 分别统计，任一 required set 缺失或失败都阻断；
- dataset、model、task、evaluator 和 runtime revision 为空时直接 `BLOCKED`；
- patch 应用失败、测试基础设施失败和断言失败使用不同错误类型。

## 8. 缺陷类别、检测器质量与问题知识库

### 8.1 Defect Class 合同

每个 defect class 必须具有：

- 定义；
- taxonomy category；
- 正例；
- 反例；
- 已知假阴性；
- detector；
- oracle；
- 最低样本量；
- 误报/漏报阈值；
- 适用 target kind；
- 不适用证明条件。

每个 defect class 必须映射到 `FUNCTIONAL_FAULT`、`RISK_EXPOSURE`、
`LATENT_DEFECT`、`VULNERABILITY`、`OMISSION`、`INCONSISTENCY`、`BOUNDARY`
或 `EXCEPTION_PATH`。无法归类的类别必须先登记为 `OTHER_DECLARED` 并进入新的
taxonomy version，不允许运行时临时添加隐式类别。

检测器质量至少验证：

- seeded defect recall；
- mutation score；
- precision estimate；
- false-negative replay；
- cross-language 或 cross-target samples；
- 规则版本和过期时间。

检测器不能证明自己充分。高风险检测器需要独立 oracle 或外部 held-out。

### 8.2 问题知识库

问题知识库不是当前运行的风险账本，也不是聊天摘要。它是跨运行、可审计、
可版本化的检测能力资产。

知识类型：

| 类型 | 用途 |
|---|---|
| `DEFECT_PATTERN` | 描述重复出现的失败结构 |
| `ROOT_CAUSE` | 描述一个根因及其影响模式 |
| `FALSE_POSITIVE` | 记录误报边界，避免未来重复误报 |
| `NON_APPLICABILITY` | 记录有证明的不适用条件 |
| `REGRESSION` | 保存可重放的历史失败案例 |
| `GUARD` | 对高风险问题增加预防性检查 |

每条 knowledge item 必须带 scope、trigger、exclusion、provenance、support、
helpful/harmful counters、confidence、validity 和 detector/regression bindings。
知识项不得只保存自然语言总结而缺少可执行证据。

首次安装使用不可变的 `knowledge-pack-v0`，内容仅来自 invariant、detector、
oracle 和 regression 的静态 registry；它不包含未经验证的 learned pattern。
后续 pack 必须通过版本化 promotion 流程生成。

### 8.3 Observation 提取

以下来源都产生 issue observation：

- 检查阶段发现的新 finding；
- 验证阶段发现的回归和失败；
- incident、poststart 或生产观察；
- independent review 新发现的问题；
- 被撤销的历史 knowledge candidate。

提取时：

1. 绑定 run、subject、candidate、phase 和 tool version；
2. 保存最小充分原始证据；
3. 提取 semantic feedback，避免把 verifier regex、内部阈值或敏感信息泄漏给学习器；
4. 生成机制 fingerprint；
5. 标记 `CONFIRMED`、`INCONCLUSIVE` 或 `FALSE_POSITIVE`；
6. 搜索 analogous surfaces；
7. 计算 canonical `record_digest`，原子写入 append-only observation journal；
8. 验证 `previous_record_digest -> record_digest` 链，并刷新 segment manifest。

Observation 写入采用 write-ahead 顺序：先持久化 observation，再改变 risk ledger
或 candidate 状态。journal 损坏、链断裂、序号重复或脱敏策略缺失均返回
`BLOCKED_EVIDENCE`，不能用“日志可后补”继续运行。

### 8.4 Candidate 生成与去重

学习器可以从 observation 生成：

- 新 detector；
- 更精确的 guard；
- 新 regression case；
- 不适用证明规则；
- 现有 detector 的排除条件；
- 现有知识与新知识的合并候选。

相似知识先聚类，再进入人工或独立评审。初始 similarity threshold 使用 `0.90`，
但它只能用于发现 merge candidate，不能自动删除知识。合并必须保留：

- 所有来源 observation；
- 正例和反例；
- 原 helpful/harmful counters；
- 适用范围；
- detector 与 regression bindings；
- supersedes 关系和回滚点。

`fingerprint` 不是原始 message 或路径的哈希。它的输入至少包含
`defect_class_id`、归一化机制类别、适用 target kind 和 fingerprint algorithm
version；绝对路径、临时目录、行号、时间戳和随机 ID 必须先归一化。算法版本变化
时生成新的 namespace，并运行旧/新 fingerprint 对照，不能静默改变历史去重语义。

Learning candidate 只能修改显式允许的 detector、guard、regression 和 knowledge
数据。不得修改 verifier、hidden tests、审批策略、release token、trust root、
当前 risk ledger 或历史 evidence。

单次出现的 observation 仍必须进入 regression corpus。它不会自动变成泛化
detector；但高频模式可以形成 detector，高风险一次性事件可以形成 `GUARD_ONLY`，
其余保持可检索的历史案例，避免用一次偶然事件污染通用规则。

### 8.5 验证与晋升门禁

知识候选必须先通过 train / validation / held-out 三分，不能在同一批失败数据上
自证。

项目默认门槛：

```text
minimum_rule_samples = 20
minimum_rule_precision = 0.90
maximum_false_trigger_rate = 0.10
heldout_required_for_new_rules = true
required mutation kill = true
required historical false-negative replay = true
duplicate detector check = true
never-fired detector audit = true
```

高风险 guard 可以在少于 20 个样本时以 `GUARD_ONLY` 激活，但必须由独立 reviewer
基于确认的复现实验批准，且不能自动升级为通用 detector。

多个 learning candidate 使用 Pareto 比较，不按单一总分直接选优。比较维度至少包括
precision、recall、false-positive rate、mutation kill、historical replay misses、
cost 和 latency。一个候选只有在任何关键维度没有不可解释回退时才能进入评审。

candidate 通过不是发布完成。新 knowledge pack 还要作为一个整体执行
`pack-level shadow replay`：

- 与当前 active pack 在同一历史 corpus 上比较命中、漏报、误报和成本；
- 对每个 required invariant 运行正向 control，证明 detector 没有因版本或 scope
  变化而失联；
- 对新增 detector 运行反例和跨 target/platform 负向控制；
- 只要任一 critical invariant 的覆盖下降、历史真缺陷漏报增加或 false-trigger
  超过阈值，整 pack 拒绝，不挑一个“平均分更高”的版本放行；
- 通过后原子发布 `knowledge-pack.lock`；旧 pack 保留可回滚引用。

知识候选状态：

```text
OBSERVED
  -> CONFIRMED
  -> GENERALIZED
  -> CANDIDATE
  -> VALIDATED
  -> ACTIVE
  -> DEPRECATED / RETIRED
```

`CANDIDATE` 和 `VALIDATED` 都不能被当前运行使用。只有已写入新 knowledge pack
的 `ACTIVE` 项才能进入下一次运行的 frozen detector set。

### 8.6 使用反馈与淘汰

每次 detector 运行后，根据结果更新 helpful/harmful counter：

- 命中真实缺陷：helpful + 1；
- 确认误报：harmful + 1；
- non-applicability 被错误应用： harmful + 1，并创建 regression；
- 长期未命中：进入 never-fired audit，并用 seeded positive control 判断是
  “确实无用”还是“运行样本未覆盖”；没有可执行正向控制的 detector 不得仅因
  未命中而自动退休；
- harmful 连续高于 helpful、precision 低于门槛或过期：标记 `DEPRECATED`；
- 被新知识替代：`superseded_by` 必须指向已验证替代项。

计数和状态更新不能直接删除历史证据。退休只改变下一次 pack 的加载集合。

Learning run 自身也必须有停止条件：

- 相同 observation set、candidate digest、policy digest 和工作区快照不得重复尝试；
- 连续无提升达到 policy 上限时停止，不生成新 pack；
- 预算耗尽返回 `INCOMPLETE_LEARNING`，不能把未跑案例算作通过；
- candidate 数量、token、时间、工具调用和存储必须有硬上限；
- 新 candidate 必须引用它解决的历史失败集合，不能只在合成案例上提升。

### 8.7 已有资料证据与取舍

本地资料复核日期：2026-11-07。以下引用均指向已冻结的本地文件或仓库快照。

| 来源 | 已核实机制 | V9.2.1 决策 |
|---|---|---|
| `self-evolving-agents-2026-10-22/调研报告-2026-10-22.md` 第 13、37-39、90-101、134-142、160-163、468-498 行 | GEPA 的 actionable feedback、Pareto 与 merge；Prime 的 stale-write、cooldown、branch fence；EvoSkill 的 feedback history 和 no-improvement stop | 采用“可行动诊断 + 历史回放 + 候选前沿”；不采用在线自改闭环 |
| `EvoSkill/src/loop/helpers.py:151-192` | feedback history 记录 proposal、Outcome、score、failure category、root cause | 由 `Issue Observation` 和 `Learning Receipt` 取代自由文本历史 |
| `EvoSkill/src/loop/runner.py:390` | 连续无改进时停止 | 明确禁止自动回流；学习周期也不能无限运行 |
| `repos/ace-agent__ace/playbook_utils.py:50-94` | playbook 使用 helpful/harmful 计数，按增量 delta 维护 | 采用带计数的知识项和 append-only 变更 |
| `ace-agent__ace/ace/core/bulletpoint_analyzer.py:150-285` | 相似度阈值 `0.90` 用于分组、去重和合并 | 仅作为候选分组阈值，不允许自动删除证据 |
| `repos/microsoft__skillopt/skillopt_sleep/consolidate.py:5-7, 71-99, 192-216` | train/val/test 隔离、held-out gate、budget skip 和 fresh replay | 用于 detector candidate 晋升与 pack-level replay，不用于当前运行自动修复 |
| `repos/microsoft__skillopt/skillopt_sleep/memory.py:15-95` | learned region 与人工内容隔离，add/delete/replace 有去重和 unmatched 记录 | 用于未来 knowledge pack 写入边界 |
| `reports/semantic-evolution/rc96-risk-repair-r2/stage2-preview-r4/check-health.json:19-33` | `min_rule_samples=20`、`min_rule_precision=0.9`、`max_false_trigger_rate=0.1`、new rule 必须有 held-out | 作为本项目的初始 detector 晋升策略 |
| `inspection-closure-targeted-supplement-20261023/TARGETED_SUPPLEMENT.md:52-55, 63, 80-85, 98-107` | requested/attempt 对账、缺结果即失败、F2P/P2P 分离、unscored 不等于答错、全 unscored 为 `INCONCLUSIVE` | 用于冻结验证矩阵和评测结果语义 |
| `whole-repo-repair-full-read-20261107/final-report.md:79-91, 107-151, 237-255` | 上游内容/行分块完备不等于逐行吃透；106 findings 归并为 9 个系统性 root groups；无证据重开必须阻断 | 问题知识库必须区分 `CONTENT-BOUND / READ-FULL / MASTERED / UNVERIFIED` |

当前明确不采纳：

- 在一次检查中边运行边更新 detector；
- 只靠单一 benchmark 分或单一 LLM judge 自动晋升知识；
- 让学习候选修改 verifier、hidden tests、审批策略或安全根；
- 用 embedding 相似度直接删除、合并知识；
- 将失败历史压缩成不可重放的摘要；
- 把一次未复现的低质量观察直接升级为通用规则。

直接复用边界：

- ACE 当前实现主要完整支持 `ADD`，`UPDATE/MERGE/DELETE` 仍有未实现或警告路径，
  因此 V9.2.1 采用明确的数据迁移和审计规则，不照搬其 curator 执行器。
- EvoSkill 的自动循环适合研究候选生成，不是本系统当前运行的控制器。
- SkillOpt Sleep 的 held-out gate 验证的是文本编辑，不证明任意项目的完整语义正确；
  V9.2.1 只采用其 split、gate、protected region 和 evidence 设计。

### 8.8 调研覆盖与信息边界

V9.2.1 复审的目录文件量（2026-11-07，排除 `.git` 与 `__pycache__`）：

```text
whole-repo-repair-full-read-20261107             182,617 files
self-evolving-agents-2026-10-22                    1,624 files
self-evolving-agents-round2-2026-10-22             1,454 files
inspection-closure-targeted-supplement-20261023      514 files
reports/semantic-evolution                        31,829 files
```

本轮重点精读的是与 V9 机制直接相关的报告、源码和验证证据，不把“文件已入账”
写成“所有文件逐行语义吃透”。信息边界如下：

- whole-repo 研究已证明 live 目标 329 个非缓存文件完成全量读取，但上游仓库的
  semantic reading 仍按纵切面推进，不能冒充全仓逐行掌握；
- EvoSkill/ACE/SkillOpt 的重点是失败历史、知识增量、门禁和受保护学习区域，
  V9.2.1 没有把它们的具体运行时当作安全沙箱；
- semantic-evolution 报告用于确认规则健康、签名评审、零开放风险和状态身份要求，
  不能替代对每个候选仓库的重新运行；
- 当前没有重新执行所有历史 benchmark、外部服务、物理断电或跨平台测试。

这些边界不会阻止 V9.2.1 的架构设计，但会阻止“所有历史资料都已语义吃透”以及
“所有上游运行时结论已验证”的过度声明。

## 9. 修复策略

### 9.1 修复分类

| 类型 | 使用条件 |
|---|---|
| `AUTO_SAFE` | 语义唯一、路径封闭、预像可验证、回滚确定 |
| `AUTO_WITH_REVIEW` | 可自动生成，但必须由独立评审确认 |
| `HUMAN_DECISION_REQUIRED` | 涉及意图、取舍、权限或外部状态 |
| `NO_AUTO_REPAIR` | 证明性缺口只能由新证据关闭 |

`HUMAN_DECISION_REQUIRED` 和 `NO_AUTO_REPAIR` 不是豁免状态，问题仍阻断完成。

### 9.2 批次冲突

以下情况阻断批次冻结：

- 多个 operation 修改同一路径但语义不同；
- 一个 operation 依赖另一个 operation 的未冻结结果；
- 修复会覆盖受保护文件或验证器；
- 生成文件被直接修改；
- 修复需要越权、网络或不可逆外部操作；
- preimage 与当前输入不一致。

冲突只能在同一冻结计划中一次性解决，不允许绕过。

### 9.3 回滚

每个操作必须有：

- preimage digest；
- postimage digest；
- 回滚动作；
- 回滚验证；
- 不可逆原因的显式记录。

无法回滚的操作必须在执行前取得明确授权，并在执行后进行外部读数对账。

## 10. 无自动回流的单次闭环规则

“一次性”不代表掩盖失败，而代表把发现、计划、修复、验证设计成单向流程。

```text
exhaustive discovery
  -> complete impact analysis
  -> complete batch plan
  -> plan preflight
  -> frozen candidate
  -> full verification
  -> independent review
  -> CLOSED or BLOCKED
```

禁止：

- 发现一个问题就立刻修一个问题；
- 每个 finding 单独跑一轮测试；
- 失败后继续在原候选上逐点打补丁；
- 验证失败后自动重新发现、重新规划或重新生成候选；
- 把“最多两次”包装成所谓一次性流程；
- 用“先发布、后续迭代”处理已发现问题；
- 用自动循环替代根因分析。

用户显式发起的新运行必须使用新的 `scope_id` 和新的完整 census。旧运行只能作为
历史证据引用，不能把旧候选作为新运行的隐式起点。

## 11. 安全、性能与可维护性

### 11.1 安全

- 目标内容视为不可信输入；
- 默认禁用网络和未授权脚本；
- 参数使用 argv，不使用拼接 shell；
- 所有路径经过根目录约束和 symbolic-link 检查；
- 秘密不进入 argv、异常、日志、缓存或 diff；
- 删除、安装、发布和外部写操作必须授权并支持对账；
- 生产对象默认只读，候选在隔离目录生成；
- knowledge item 中的原始 finding、日志和网页内容只作数据，不执行其中指令；
- active knowledge pack 必须签名或绑定可信 digest，加载前验证 scope 和有效期；
- 最终发布使用 GitHub Actions OIDC + Sigstore keyless bundle，校验精确
  certificate identity 和 OIDC issuer；`ed25519-detached` 只作为显式回退；
- learning candidate 不得修改 verifier、hidden tests、policy、trust root 或 approval；
- observation/evidence 日志按敏感数据处理，设置保留周期和脱敏策略。

### 11.2 性能

- 按内容摘要和策略版本缓存；
- 缓存不能跳过最终候选验证；
- train / validation / held-out 使用互斥 cache namespace；
- 相同 observation、candidate 和 policy digest 不得重复学习尝试；
- 分区结果通过 coverage digest 合并；
- 高风险 cell 优先，但不能挤占低频必需 cell；
- 超时和预算耗尽返回 `BLOCKED`，不能静默跳过。

### 11.3 可维护性

- 每种 target kind 一个 adapter；
- 每个 invariant 一个 registry 条目；
- 每个 detector 一个版本化包；
- 每个 knowledge item、knowledge pack 和 learning receipt 都带 schema version；
- 每个 repair class 一个受限 adapter；
- 每个 oracle 独立于被检查实现；
- 配置、schema、测试和文档一起版本化；
- 所有公共对象带 `schema_version`。

## 12. 建议目录结构

```text
F:\Codex\skills-candidates\inspection-closure-v9\
├── SKILL.md
├── agents\
│   └── openai.yaml
├── core\
│   ├── control_plane.py
│   ├── state_machine.py
│   ├── identity.py
│   ├── budget.py
│   └── orchestrator.py
├── adapters\
│   ├── base.py
│   ├── skill_adapter.py
│   ├── plan_adapter.py
│   ├── article_adapter.py
│   └── project_adapter.py
├── census\
│   ├── resources.py
│   ├── claims.py
│   ├── graph.py
│   ├── coverage.py
│   └── taxonomy.py
├── detectors\
│   ├── registry.py
│   ├── static_checks.py
│   ├── dynamic_checks.py
│   ├── behavior_checks.py
│   └── security_checks.py
├── impact\
│   ├── graph_builder.py
│   ├── frontier.py
│   └── completeness.py
├── repair\
│   ├── registry.py
│   ├── planner.py
│   ├── conflict_graph.py
│   ├── preflight.py
│   ├── executor.py
│   └── rollback.py
├── verification\
│   ├── matrix.py
│   ├── runners.py
│   ├── oracle_quality.py
│   └── evidence_trust.py
├── closure\
│   ├── risk_entry.py
│   ├── risk_ledger.py
│   ├── completion.py
│   └── release_claim.py
├── knowledge\
│   ├── observations.py
│   ├── fingerprints.py
│   ├── patterns.py
│   ├── dedup.py
│   ├── candidates.py
│   ├── replay.py
│   ├── promotion.py
│   ├── packs.py
│   └── retirement.py
├── contracts\
│   ├── subject-manifest.schema.json
│   ├── required-source.schema.json
│   ├── defect-taxonomy.schema.json
│   ├── finding.schema.json
│   ├── impact-graph.schema.json
│   ├── repair-batch.schema.json
│   ├── verification-matrix.schema.json
│   ├── risk-entry.schema.json
│   ├── risk-ledger.schema.json
│   ├── issue-observation.schema.json
│   ├── knowledge-item.schema.json
│   ├── knowledge-pack.schema.json
│   ├── learning-candidate.schema.json
│   └── release-claim.schema.json
├── policies\
│   ├── invariant-registry.json
│   ├── defect-taxonomy.json
│   ├── defect-registry.json
│   ├── repair-registry.json
│   ├── behavior-policy.json
│   ├── runtime-policy.json
│   └── knowledge-policy.json
├── scripts\
│   ├── inspect.py
│   ├── repair.py
│   ├── verify.py
│   ├── close.py
│   └── learn.py
├── tests\
│   ├── contract\
│   ├── unit\
│   ├── integration\
│   ├── negative\
│   ├── heldout\
│   ├── mutation\
│   └── knowledge\
└── docs\
    ├── architecture.md
    ├── threat-model.md
    └── operating-guide.md
```

## 13. 标准产物

当前 stable-local 检查在独立目录生成：

```text
run-state.json
subject-manifest.json
required-sources.jsonl
detections.json
impact-graph.json
risk-ledger.json
taxonomy-coverage.json
taxonomy-qualification.json
character-coverage.json
punctuation-ledger.jsonl
whitespace-control-ledger.jsonl
byte-ledger.jsonl
codepoint-ledger.jsonl
line-ledger.jsonl
unit-ledger.jsonl
binary-structure-ledger.jsonl
projection-ledger.jsonl
uncovered-character-ranges.json
write-ahead-journal.jsonl
write-ahead-journal-check.json
observations.jsonl
observation-journal-manifest.json
summary.json
```

Repair 另外生成 `repair-batch.json`、`candidate-manifest.json` 和
`final-risk-ledger.json`；提供评估证据时生成 `verification-matrix.json`。
所有 JSON 对象使用 canonical serialization；所有 digest 必须可重算。

Stable-local release 在 release 目录生成：

```text
package-manifest.json
review-packet.json
independent-review.json
release-claim.json
install-receipt.json
release-history.jsonl
blocked-review.json
blocked-claim.json
blocked-install.json
```

外部验证输入不属于 CLI 输出：

```text
reviewer-attestation.json
reviewer-attestation.sigstore.json
sigstore-verifier executable
```

Ed25519 回退路径使用 attestation、detached signature 和 public key，不使用
Sigstore bundle。

`release-history.jsonl` 只追加 `CLAIM`、`INSTALL` 和 `INSTALL_BLOCKED` 记录，
每条记录携带序号、前序摘要和当前摘要。安装失败恢复旧目标并写
`blocked-install.json`；成功替换保留旧目标 rollback tree。当前 CLI 不提供自动
回滚命令，后续人工回滚属于独立的高风险操作。

Learning Clock 在运行目录之外产生：

```text
learning-candidates.jsonl
knowledge-pack.json
knowledge-pack.lock
learning-receipts.jsonl
knowledge-replay-report.json
```

当前运行只能读取 `knowledge-pack.lock` 指向的且 digest 匹配的 pack。

## 14. 完成与发布分级

### A. `CHECKED`

全量 discovery 已执行，issue ledger 已形成，但仍有开放项。不可发布。

### B. `REPAIRED_CANDIDATE`

一个冻结批次已应用，候选已通过同一默认 detector 集合的重跑且没有保留开放
finding。它不是安装包、独立评审或发布声明，仍不可安装。

### C. `PASS_FOR_DECLARED_UNIVERSE`

冻结范围内无开放项、无漏源、无 residual risk，要求的验证矩阵全部通过。这是
发布门禁分类，不是当前 `run_inspection.py` 的直接成功状态。

### D. `RELEASE_READY`

在 C 的基础上，独立评审通过，发布声明不超出已验证范围。

### E. `UNIVERSAL_CERTAINTY`

系统永不宣称该状态。未知缺陷类别不能被有限检查证明为空。

### F. Stable-local release receipts

最终 release 链为 `package -> GitHub Actions OIDC + Sigstore bundle
verification -> review -> claim -> install`。`sigstore-keyless` 是 CLI 默认
验证方式；`ed25519-detached` 是保留的显式本地回退。Review verdict 是 `PASS`
且状态为 `INDEPENDENT_REVIEW`；claim 状态为 `RELEASE_READY` 且状态为
`CLOSED_FOR_DECLARED_UNIVERSE`；install receipt 状态为 `INSTALLED`；外部验证
receipt 状态为 `VERIFIED`。任何 release 命令验证失败时写
`blocked-<command>.json`，状态为 `BLOCKED_VERIFICATION`。

`package-manifest.json` 绑定精确文件集与 tree digest；
`independent-review.json` 绑定 review subject、embedded `external_signature`
receipt、风险门禁、candidate 和 verification；`release-claim.json` 绑定 review
以及 Sigstore `bundle_sha256` 和 `verifier_command_digest`；
`install-receipt.json` 记录 staging、read-back、rollback tree 和安装后 digest。
`release-history.jsonl` 以序号和前序摘要形成 append-only hash chain。

Sigstore attestation 的 `reviewer` 必须等于精确 certificate identity，
`issuer` 必须等于精确 GitHub Actions OIDC issuer。`trust_root_id` 由
verification method、certificate identity 和 OIDC issuer 派生，不接受调用方
自报。Claim 只覆盖已冻结且已评审的 universe；它不等于 universal certainty、
超出已验证平台 receipt 的安装成功或物理断电安全。Bundle、verifier、命令、identity、
issuer、review subject 或 candidate 任一变化都使下游 claim 失效。
`verifier_command_digest` 只绑定 argv（含 executable path），不绑定 binary
bytes；runner image/toolchain digest 必须作为独立的 frozen environment evidence。

## 15. 验收标准

V9.2.1 的最低验收条件：

1. 所有 target adapter 至少各有一个真实对象试点。
2. 所有 required source 都有终态处置。
3. 所有 finding 进入风险账本，severity 不妨碍闭合要求。
4. accepted、deferred、INFO、residual 和手工豁免不能造成 PASS。
5. repair batch 冲突为零或按同一计划确定性解决。
6. candidate 有完整 preimage/postimage 和回滚证据。
7. verification matrix 的 required cells 全部执行。
8. 行为、runtime 和 lifecycle 缺口均保持阻断。
9. scope、issue、batch、candidate、verification 和 ledger digest 相互绑定。
10. 独立 reviewer 不能是 producer，且必须重算关键摘要。
11. 任何漏源、证据篡改、摘要篡改、未闭合项和高风险冒充均被负向测试捕获。
12. 系统测试通过不能覆盖业务风险账本；两个结论分别报告。
13. 状态图中不存在 `FULL_VERIFICATION -> repair/discovery` 的自动边。
14. 验证失败必须是终态 `BLOCKED_VERIFICATION`，后续工作只能由用户显式开启新的运行。
15. 每个检查、验证或 incident 新问题都写入 append-only observation journal。
16. 当前运行固定一个 knowledge pack digest，运行中不得激活新 detector。
17. Learning candidate 使用互斥的 train、validation、held-out 数据，并阻断泄漏。
18. 新知识只有在独立 review 和规则健康门禁通过后才能进入 active pack。
19. 误报、失败重放和 harmful feedback 必须能更新、降级或退休知识项。
20. knowledge pack、detector pack 和 regression corpus digest 与 run scope 绑定。
21. 每个 finding 都有唯一 root lineage，root 关闭必须覆盖全部子项和 analogous surfaces。
22. observation journal 的序号、前一记录摘要和当前记录摘要可连续重算，截断或篡改返回 `BLOCKED_EVIDENCE`。
23. observation、knowledge item、knowledge pack 和 learning candidate 的 `schema_version` 与 fingerprint 算法版本均被冻结和校验。
24. 新 knowledge pack 通过整体 shadow replay；任一 required invariant 覆盖下降时整 pack 拒绝。
25. never-fired audit 有 seeded positive control，不能单凭“长期未命中”退休关键 detector。
26. 所有 requested evaluation case 均被 `PASS/FAIL/TIMEOUT/INFRA_ERROR/UNSCORED/MISSING` 对账；全 unscored 或全基础设施失败只能是 `INCONCLUSIVE/BLOCKED`。
27. 输入、环境、配置、工具或 adapter digest 在运行中变化时，立即 `BLOCKED_STALE_INPUT`，不存在自动回到 `SCOPE_FROZEN` 的边。
28. taxonomy coverage matrix 的每个 required cell 都有 detector、独立 oracle 或经过证据证明的 `NOT_APPLICABLE`；缺失单元必须是 `BLOCKED_TAXONOMY`。
29. 每个 finding 都绑定 taxonomy category；新增 target kind、adapter 或 category 时未映射单元不能继承旧的 `NOT_APPLICABLE`。

## 16. 实施计划

建议实现根目录：

```text
F:\Codex\skills-candidates\inspection-closure-v9
```

### Task 1：冻结合同与 registry

**Files**

- Create: `contracts/subject-manifest.schema.json`
- Create: `contracts/required-source.schema.json`
- Create: `contracts/finding.schema.json`
- Create: `contracts/risk-entry.schema.json`
- Create: `contracts/risk-ledger.schema.json`
- Create: `contracts/defect-taxonomy.schema.json`
- Create: `policies/invariant-registry.json`
- Create: `policies/defect-taxonomy.json`
- Test: `tests/contract/test_risk_contracts.py`
- Test: `tests/contract/test_defect_taxonomy.py`

**Interfaces**

- Produces: `RiskEntry`, `RiskLedger`, `RequiredSource`, `SubjectManifest`,
  `DefectTaxonomy`, `TaxonomyCoverage`
- Consumes: canonical JSON and SHA-256 helpers

**步骤**

- [ ] 写 schema 校验和 open/accepted/residual 负向测试。
- [ ] 写 required-source 漏项和 digest 篡改测试。
- [ ] 写 taxonomy category、required cell、未映射单元和新类别阻断测试。
- [ ] 实现 canonical digest、closure validator 和 registry 解析。
- [ ] 运行 `pytest tests/contract/test_risk_contracts.py -q`。
- [ ] 全测试通过后提交合同。

### Task 2：控制面与状态机

**Files**

- Create: `core/control_plane.py`
- Create: `core/state_machine.py`
- Create: `core/identity.py`
- Create: `core/budget.py`
- Test: `tests/unit/test_state_machine.py`

**Interfaces**

- Produces: `freeze_scope()`, `transition()`, `invalidate_downstream()`,
  `consume_budget()`
- Consumes: subject manifest、policy digests、budget policy

**步骤**

- [ ] 写非法状态跳转、digest 变化失效和预算耗尽测试。
- [ ] 实现有限状态机和下游失效规则。
- [ ] 写输入漂移进入 `BLOCKED_STALE_INPUT` 且不能自动回到 `SCOPE_FROZEN` 的测试。
- [ ] 写从 `FULL_VERIFICATION` 到 discovery/repair 的自动边必须被拒绝的测试。
- [ ] 实现预算耗尽 `BLOCKED`，禁止返回 skipped success。
- [ ] 运行 `pytest tests/unit/test_state_machine.py -q`。
- [ ] 更新状态机文档并提交。

### Task 3：目标适配器

**Files**

- Create: `adapters/base.py`
- Create: `adapters/skill_adapter.py`
- Create: `adapters/plan_adapter.py`
- Create: `adapters/article_adapter.py`
- Create: `adapters/project_adapter.py`
- Test: `tests/integration/test_target_adapters.py`

**Interfaces**

- Produces: `build_manifest()`, `build_graph()`, `bind_detectors()`,
  `bind_repairs()`, `bind_verification()`
- Consumes: `SubjectManifest`

**步骤**

- [ ] 为四种 target kind 各写最小 fixture。
- [ ] 写未知 target kind 和 unsupported capability 阻断测试。
- [ ] 实现统一 adapter protocol 和四个适配器。
- [ ] 验证所有目标使用同一 risk model。
- [ ] 验证每个 adapter 输出完整的 taxonomy applicability 声明。
- [ ] 运行 `pytest tests/integration/test_target_adapters.py -q`。

### Task 4：Total Census 与 Collect-All Detection

**Files**

- Create: `census/resources.py`
- Create: `census/claims.py`
- Create: `census/graph.py`
- Create: `census/coverage.py`
- Create: `census/taxonomy.py`
- Create: `detectors/registry.py`
- Test: `tests/unit/test_census.py`
- Test: `tests/unit/test_detector_isolation.py`
- Test: `tests/unit/test_taxonomy_coverage.py`

**Interfaces**

- Produces: `census_subject()`, `required_sources()`, `build_taxonomy_coverage()`,
  `assert_taxonomy_complete()`, `run_all_detectors()`
- Consumes: target adapter、detector registry

**步骤**

- [ ] 写未知资源、重复 source、detector 异常和部分失败测试。
- [ ] 写每个 target kind × category × evidence plane 的 required-cell 覆盖测试。
- [ ] 写空 detector、空 oracle、缺失 N/A 证明和新增类别的阻断测试。
- [ ] 实现 file/section/symbol/claim 的 resource census。
- [ ] 实现并行 collect-all；单 detector 失败不能停止其他 detector。
- [ ] 校验 required sources 与 ledger 来源集合双向一致。
- [ ] 运行相关单元测试。

### Task 5：全局影响分析

**Files**

- Create: `impact/graph_builder.py`
- Create: `impact/frontier.py`
- Create: `impact/completeness.py`
- Test: `tests/unit/test_impact_closure.py`

**Interfaces**

- Produces: `build_impact_graph()`, `impact_frontier()`, `assert_complete()`
- Consumes: subject graph、findings、repair bindings

**步骤**

- [ ] 写调用者、接口、测试、配置、文档和外部依赖影响测试。
- [ ] 实现跨模块和跨语言影响边。
- [ ] 写 root identity、finding lineage、shared root 和 analogous surface 测试。
- [ ] 为无影响结论生成可验证证明。
- [ ] 阻断未分类 frontier。
- [ ] 运行影响闭包测试。

### Task 6：单批修复计划与事务执行

**Files**

- Create: `repair/registry.py`
- Create: `repair/planner.py`
- Create: `repair/conflict_graph.py`
- Create: `repair/preflight.py`
- Create: `repair/executor.py`
- Create: `repair/rollback.py`
- Test: `tests/integration/test_batch_repair.py`

**Interfaces**

- Produces: `plan_batch()`, `preflight_batch()`, `assert_conflict_free()`, `apply_batch()`,
  `rollback_batch()`
- Consumes: complete finding set、impact graph、repair registry

**步骤**

- [ ] 写多问题同文件冲突、preimage 漂移和故障回滚测试。
- [ ] 实现所有 finding 进入一个冻结计划。
- [ ] 实现 preflight：preimage、冲突、oracle、runner、权限和环境一次校验。
- [ ] 实现候选树、路径约束、symlink 检查和 atomic replace。
- [ ] 实现整批失败回滚和 candidate digest。
- [ ] 运行集成测试。

### Task 7：冻结验证矩阵

**Files**

- Create: `verification/matrix.py`
- Create: `verification/runners.py`
- Create: `verification/oracle_quality.py`
- Create: `verification/evidence_trust.py`
- Test: `tests/integration/test_verification_matrix.py`

**Interfaces**

- Produces: `build_verification_matrix()`, `run_matrix()`,
  `verify_candidate_binding()`
- Consumes: candidate manifest、verification policy、oracle registry

**步骤**

- [ ] 写缺少 plane、stale evidence、oracle self-reference 和 timeout 测试。
- [ ] 写 requested/attempt 对账、六态结果、F2P/P2P 分离和全 unscored 测试。
- [ ] 实现静态、测试、行为、安全、runtime 和 lifecycle runner。
- [ ] 实现 required cell 与 coverage digest 双向校验。
- [ ] 实现 evidence subject/candidate/policy 绑定。
- [ ] 运行矩阵测试。

### Task 8：零开放风险与发布裁决

**Files**

- Create: `closure/risk_entry.py`
- Create: `closure/risk_ledger.py`
- Create: `closure/completion.py`
- Create: `closure/release_claim.py`
- Test: `tests/negative/test_zero_open_risk.py`

**Interfaces**

- Produces: `build_risk_ledger()`, `assert_zero_open()`,
  `classify_release_claim()`
- Consumes: required sources、findings、verification receipts、impact closure

**步骤**

- [ ] 写 open-low、accepted、deferred、INFO、residual、漏源和 digest 篡改测试。
- [ ] 实现四个合法关闭状态及各自证据要求。
- [ ] 实现 completion 与 ledger digest 绑定。
- [ ] 实现 release claim 不得超过验证范围。
- [ ] 运行全部负向测试。

### Task 9：编排器与 CLI

**Files**

- Create: `core/orchestrator.py`
- Create: `scripts/inspect.py`
- Create: `scripts/repair.py`
- Create: `scripts/verify.py`
- Create: `scripts/close.py`
- Test: `tests/integration/test_end_to_end.py`

**Interfaces**

- Produces: `run_inspection()`, `run_repair_batch()`,
  `run_full_verification()`, `run_closure()`
- Consumes: Tasks 1-8

**步骤**

- [ ] 写成功闭环、开放项阻断、验证失败直接终止、自动回流被拒绝和摘要篡改测试。
- [ ] 实现单入口编排和标准输出目录。
- [ ] 禁止跳过阶段或从部分状态直接发布。
- [ ] 生成 `summary.json` 和全部当前标准 JSON/JSONL 产物。
- [ ] 运行端到端测试。

### Task 10：真实对象试点与冻结验收

**Files**

- Create: `config/pilot-targets.json`
- Create: `config/pilot-cases.json`
- Create: `artifacts/pilot-report.json`
- Create: `artifacts/verification-report.md`

**步骤**

- [ ] 选择一个技能、一个方案、一篇文章和一个项目。
- [ ] 运行全量普查、影响分析、批量修复和验证。
- [ ] 记录发现数、关闭数、开放数、假阳性率、漏检率、成本和时间。
- [ ] 对 open risk、行为、runtime 和 lifecycle 缺口分别给出阻断结果。
- [ ] 独立 reviewer 重算摘要并给出最终裁决。
- [ ] 只有满足全部验收条件时冻结 V9.2.1 基线。

### Task 11：问题知识库与检测器学习

**Files**

- Create: `knowledge/observations.py`
- Create: `knowledge/fingerprints.py`
- Create: `knowledge/journal_chain.py`
- Create: `knowledge/candidates.py`
- Create: `knowledge/replay.py`
- Create: `knowledge/pack_replay.py`
- Create: `knowledge/promotion.py`
- Create: `knowledge/packs.py`
- Create: `knowledge/retirement.py`
- Create: `contracts/issue-observation.schema.json`
- Create: `contracts/knowledge-item.schema.json`
- Create: `contracts/knowledge-pack.schema.json`
- Create: `contracts/learning-candidate.schema.json`
- Create: `policies/knowledge-policy.json`
- Test: `tests/knowledge/test_observation_journal.py`
- Test: `tests/knowledge/test_journal_chain.py`
- Test: `tests/knowledge/test_pack_replay.py`
- Test: `tests/knowledge/test_knowledge_promotion.py`
- Test: `tests/knowledge/test_knowledge_retirement.py`

**Interfaces**

- Consumes: closed `risk_ledger`, verification receipts, incidents and active
  knowledge pack.
- Produces: `observe_issue()`, `fingerprint_issue()`, `build_learning_candidate()`,
  `replay_knowledge_candidate()`, `promote_knowledge()`, `load_frozen_pack()`.

**步骤**

- [ ] 写 observation journal：检查、验证和 incident 新问题都能落盘，敏感字段脱敏。
- [ ] 写 observation 三态、schema version、hash-chain、序号重复和截断恢复测试。
- [ ] 从静态 registry 生成不可变 `knowledge-pack-v0`，并验证初始 detector 映射完整。
- [ ] 写 fingerprint + analogous surface 测试，禁止把单个字符串直接升级成通用规则。
- [ ] 写 fingerprint 版本迁移测试，证明旧知识不会被新算法静默重解释。
- [ ] 写 train/validation/held-out 泄漏测试，重叠案例必须 `BLOCKED`。
- [ ] 写 detector candidate 的 precision、recall、false-trigger、mutation 和 budget 门禁。
- [ ] 写 whole-pack shadow replay，任一 critical invariant 覆盖下降时拒绝发布。
- [ ] 写 active pack 的 version/digest/supersedes/expiry 测试。
- [ ] 写 harmful counter、seeded never-fired audit 和 retirement 测试。
- [ ] 写“当前运行不能看到新 pack”的隔离测试。
- [ ] 写“验证阶段发现新问题只记录并阻断，不自动重返修复”的端到端测试。
- [ ] 运行全部 knowledge 测试。
- [ ] 运行历史 corpus replay 和 held-out replay。
- [ ] 独立 reviewer 批准后才生成新的 `knowledge-pack.lock`。

## 17. 风险控制

| 风险 | 预防 | 检测 | 失败处理 |
|---|---|---|---|
| 检测器漏报 | 独立 oracle、seeded recall、mutation、held-out | 假阴性回放和覆盖率审计 | 保持 open，阻止完成 |
| 修复批次冲突 | conflict graph、路径所有权 | 同文件多语义写入测试 | 批次不冻结 |
| 修复引入新缺陷 | 预像校验、属性/回归/安全矩阵 | candidate 全量验证 | 整批回滚 |
| 证据过期 | digest 绑定 subject/policy/candidate | stale-evidence 检查 | 下游失效 |
| 用 INFO 逃避闭合 | 公共 schema 不提供可行动 INFO lane | schema 和 negative tests | 拒绝产物 |
| 未知对象类型被跳过 | target-adapter coverage invariant | adapter completeness audit | 生成阻断项 |
| 缺陷类别漏检 | versioned defect taxonomy、required-cell coverage matrix | taxonomy/category/adapter mutation tests | `BLOCKED_TAXONOMY` |
| 输入漂移触发隐式重跑 | digest 变化即终态、禁止自动回 `SCOPE_FROZEN` | stale-input 状态机可达性测试 | `BLOCKED_STALE_INPUT` |
| 成本导致漏检 | 固定 coverage quotas | budget/coverage 双审计 | BLOCKED |
| 自评审 | producer/evaluator 分离 | 身份和独立性检查 | 不发布 |
| 无限修复循环 | 验证后无回流边、批次冻结后不可改、明确新运行边界 | 状态机可达性测试 | 验证失败直接 BLOCKED |
| 虚假全知声明 | 声明限定冻结问题宇宙 | release claim 分类 | 降级或阻断 |
| 知识库被恶意内容污染 | 脱敏、data-only 边界、provenance 和独立审批 | prompt-injection/secret 测试 | 候选拒绝，当前运行不变 |
| observation 写入丢失或撕裂 | 先写 journal 再推进状态、原子追加、hash chain、恢复校验 | 断电/截断/重复序号负向测试 | `BLOCKED_EVIDENCE`，不得继续 |
| observation 三态被压成布尔值 | schema 固定 `CONFIRMED/INCONCLUSIVE/FALSE_POSITIVE` | schema 与迁移测试 | 拒绝产物 |
| fingerprint 算法漂移 | algorithm version、旧新 fingerprint 对照、独立 namespace | 历史去重 replay | 不晋升、保持旧版本 |
| 训练与验证泄漏 | 任务 ID/内容双去重，隔离 split namespace | 重叠和交叉重放测试 | 候选不得晋升 |
| 单次误报被泛化 | 支持度、反例、precision 和 harmful counter | 历史 replay + false-positive controls | 保持 candidate 或 retire |
| detector 过拟合历史 | held-out、跨 target/平台样本、mutation | 独立 held-out gate | 不进入 active pack |
| 整包升级反而降级检测 | pack-level shadow replay、required invariant coverage diff | 新旧 pack 同 corpus 对照 | 整 pack 拒绝并回滚引用 |
| 评测错误被算成效果 | requested/attempt 对账、六态结果、F2P/P2P 分离 | 分母差异、全 unscored、超时和基础设施失败测试 | `INCONCLUSIVE/BLOCKED` |
| 知识库无限膨胀 | similarity grouping、expiry、never-fired audit | pack size/budget audit | 合并或退休，不删除证据 |
| 知识跨 scope 污染 | scope-bound knowledge item | scope mismatch 测试 | detector 不加载 |
| 学习循环自身失控 | no-improvement limit、candidate digest cache、硬预算 | 相同快照重试和预算测试 | `INCOMPLETE_LEARNING` |

## 18. 最终验收公式

```text
RELEASE_READY
  = scope_locked
  ∩ all_target_kinds_resolved
  ∩ required_sources_complete
  ∩ defect_taxonomy_coverage_complete
  ∩ every_finding_has_declared_taxonomy_category
  ∩ no_input_digest_drift
  ∩ issue_ledger_complete
  ∩ every_finding_has_one_root_lineage
  ∩ every_root_closed_with_descendant_evidence
  ∩ impact_graph_closed
  ∩ repair_batch_applied
  ∩ candidate_identity_current
  ∩ verification_matrix_complete
  ∩ evidence_digests_valid
  ∩ open_risk_count == 0
  ∩ missing_sources == 0
  ∩ residual_risks == 0
  ∩ independent_review_current
  ∩ release_claim_not_overstated
  ∩ no_automatic_transition_from_verification_to_repair
  ∩ no_automatic_transition_from_stale_input_to_census
  ∩ knowledge_pack_digest_matches_frozen_scope
  ∩ all_new_issues_persisted_to_observation_journal
  ∩ observation_journal_hash_chain_valid
  ∩ observation_and_pack_schema_versions_bound
  ∩ active_knowledge_pack_passed_whole_pack_replay
  ∩ required_invariant_detector_coverage_not_decreased
  ∩ requested_evaluation_cases_fully_accounted
```

只要有一个条件不成立，结果只能是 `CHECKED`、`REPAIRED_CANDIDATE` 或 `BLOCKED`，
不能是 `RELEASE_READY`。

## 19. 结论

V9.2.1 的核心设计是：

```text
先建立完整分母
再用 versioned taxonomy 证明所有 required 缺陷类别都有检测、oracle 或 N/A 证明
再一次性发现全部已知问题
再一次性分析全局影响
再一次性生成完整修复批次
再一次性完成全量验证
最后由零开放风险账本和独立评审决定是否关闭
检查结束后再把新问题沉淀为 knowledge item / detector candidate
新 pack 整体 shadow replay 通过后原子发布
下一个显式运行读取新的 frozen knowledge pack
```

它同时解决两个问题：

- 当前运行不会通过自动回流无限重复检查—修复—再检查；
- 当前运行发现的新问题不会被丢掉，而会进入长期问题知识库，并在 held-out 和
  regression replay、whole-pack replay 和独立评审通过后升级下一次运行的检测能力。
- 过程本身可审计：每个 observation 都有三态、schema/version、记录摘要和
  hash chain；每个 knowledge pack 都有父版本、运行合同和可回滚 lock。

系统不会假装知道未知缺陷不存在，但不会遗漏、隐藏或延期任何已经识别出的缺陷，
任何类别缺口都会以 `BLOCKED_TAXONOMY` 留在分母中，输入漂移也只能终态阻断，
不会把一次发现或一次输入变化变成自我运行的无限闭环。
