"""异步任务入队辅助

- 配置了 RQ 队列(RQ_ENABLED=true)时,任务交给 rq-worker 异步执行
- 无队列(测试/轻量部署)或 Redis 入队失败时,降级为当前线程同步执行,
  保证攻击上报等主流程永远不被队列故障阻塞
"""
from flask import has_app_context, current_app


def enqueue(func, *args, **kwargs):
    """将顶层任务函数入队;不满足异步条件时同步调用。"""
    q = None
    if has_app_context():
        q = getattr(current_app, 'task_queue', None)
    if q is None:
        return func(*args, **kwargs)
    try:
        return q.enqueue(func, *args, **kwargs)
    except Exception:
        current_app.logger.exception(
            '任务入队失败,降级同步执行: %s', getattr(func, '__name__', func)
        )
        return func(*args, **kwargs)
