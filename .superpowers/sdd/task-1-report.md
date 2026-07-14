# Task 1：抽取真服务 E2E 生命周期

## RED

在 `python` 目录执行：

```text
python -B -m unittest test_gohttpx.GoHTTPXE2ETests.test_real_service_starts_and_removes_its_temp_exe -v
```

结果：失败，`NameError: name 'GoHTTPXService' is not defined`；该错误位于新增测试创建服务的语句，符合预期。

## GREEN 与回归

同一单测在实现后执行：

```text
python -B -m unittest test_gohttpx.GoHTTPXE2ETests.test_real_service_starts_and_removes_its_temp_exe -v
```

结果：`Ran 1 test in 19.255s`，`OK`。

完整真实 E2E 在 `python` 目录执行：

```text
python -B -m unittest test_gohttpx.GoHTTPXE2ETests -v
```

结果：`Ran 14 tests in 21.689s`，`OK`。

## 改动文件

- `python/e2e_support.py`：新增测试专用 `GoHTTPXService`、回环端口预留和 health 轮询；每个实例仅管理其临时 EXE 与子进程。
- `python/test_gohttpx.py`：新增 EXE 清理生命周期测试，并让现有 E2E fixture 使用该服务对象。

未修改 `api.go`；其既有未提交空白改动仍保留。

## 自审

- 服务仅监听 `127.0.0.1`，端口通过回环 socket 临时预留。
- health 请求显式使用 `trust_env=False`。
- 临时 EXE 由 `mkstemp` 唯一命名、解析为绝对路径；`close()` 只终止实例自身进程并删除该路径。
- `python/gohttpx.py` 未导入测试辅助模块，未改生产端点、协议或 SDK 公共 API。

## 顾虑

需求指定的根目录命令：

```text
python -B -m unittest python.test_gohttpx.GoHTTPXE2ETests -v
```

在未改动前后均因既有 `python/test_gohttpx.py` 的 `from gohttpx import ...` 缺少模块搜索路径而失败（`ModuleNotFoundError: gohttpx`）。为避免扩大本任务范围，未改测试模块的既有导入约定；从 `python` 目录执行等价的 E2E 命令已通过。

## 审查修复追加

- `test_real_service_starts_and_removes_its_temp_exe` 现在在保存 `exe_path` 后以 `try/finally` 执行 health 断言；断言失败时仍会调用 `service.close()`，随后断言该保存路径不存在。
- 覆盖修复的测试：`python -B -m unittest test_gohttpx.GoHTTPXE2ETests.test_real_service_starts_and_removes_its_temp_exe -v`（在 `python` 目录）通过：`Ran 1 test in 20.843s`，`OK`。
- 根目录标准命令：`python -B -m unittest discover -s python -p "test_gohttpx.py" -v` 通过：`Ran 62 tests in 54.736s`，`OK`。
- 修复提交：`test: 确保 E2E 生命周期测试总会清理`。
