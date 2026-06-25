# pre-commit-action

## 简介

安装 pre-commit 并对代码仓库执行钩子检查。

## 输入参数

| 参数 | 说明 | 必填 | 默认值 |
|------|------|------|--------|
| extra_args | pre-commit run 的额外参数 | 否 | `--all` |

## 输出参数

| 参数 | 说明 |
|------|------|
| result | 运行结果：success 或 failed |
| checked_files | 检查的文件范围 |

## 使用示例

```yaml
steps:
  - name: official_checkout
    uses: official_checkout

  - name: setup-python
    uses: setup-python

  - name: 运行 pre-commit
    uses: pre-commit-action
    with:
      extra_args: '--all'
```

## 注意事项

- 运行前需先使用 `official_checkout` 检出代码
- 运行前需先使用 `setup-python` 配置 Python 环境
- 项目根目录需包含 `.pre-commit-config.yaml` 配置文件
