---
id: project/php2shell-fixer
type: project
scope: project
title: 'Project: php2shell-fixer'
slug: php2shell-fixer
tags:
  - project-hub
refs: []
status: active
repo_url: https://github.com/turovskiy/php2shell-fixer.git
created: "2026-10-26T11:31:26Z"
updated: "2026-10-26T11:31:26Z"
confidence: 0.42
review: unreviewed
tier: supporting
summary: Хаб проекту **php2shell-fixer** — структурний вузол, до якого реферять усі episode/decision цього репозиторію (кластеризація графа).
---

# Project: php2shell-fixer

Хаб проекту **php2shell-fixer** — структурний вузол, до якого реферять усі episode/decision цього репозиторію (кластеризація графа).

## Members

```dataview
LIST
FROM "projects/php2shell-fixer"
WHERE type = "episode" OR type = "decision"
SORT file.ctime DESC
```