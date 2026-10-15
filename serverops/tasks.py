"""服务器运维模块的 Celery 任务。

为什么必须异步：批量下发几十台机器（Windows 走 WinRM，握手就很慢）动辄几分钟，
而 nginx 的读超时远小于此；大模型是思考型（Qwen3 系），单次问答 10~60s。
两者都只能"提交 → 轮询"，不能在 HTTP 请求里同步等。

注意 Celery 是 -P solo 单 worker：一个长任务会独占整个 worker。故这里对
超时上限做了硬约束（TIMEOUT_CHOICES 最大 1800s），并且在任务里绝不重试——
重试一条 `rm -rf` 是不可接受的。
"""
import logging

from celery import shared_task

logger = logging.getLogger(__name__)

# 任务级的硬超时上限，与 views.TIMEOUT_CHOICES 的最大值保持一致
MAX_TIMEOUT_SEC = 1800


@shared_task(name='serverops.run_job')
def run_serverops_job(job_id):
    """执行一次批量下发。任何异常都吞在任务里并落到 job.error，绝不向上抛。

    不声明 autoretry：这条任务下发的是【真实的变更命令】，"失败自动重试"
    意味着可能把同一条 rm/restart 再跑一遍。要看结果就去看逐台明细。
    """
    from django.utils import timezone

    from serverops.models import ServerOpsJob
    from serverops.services import runner

    job = ServerOpsJob.objects.filter(pk=job_id).first()
    if not job:
        logger.warning('serverops 任务不存在: %s', job_id)
        return {'ok': False, 'error': '任务不存在'}
    if job.status != 'pending':
        # 双投递/重复点击时挡一下：已经在跑或已跑完的，不能再跑一遍
        logger.warning('serverops 任务 #%s 状态为 %s，跳过重复执行', job.pk, job.status)
        return {'ok': False, 'error': '任务状态为 %s，未重复执行' % job.status}

    try:
        runner.execute_job(job)
    except Exception as exc:
        logger.exception('serverops 任务 #%s 执行异常', job.pk)
        job.status = 'failed'
        job.error = ('任务执行异常：%s: %s' % (type(exc).__name__, exc))[:4000]
        job.finished_at = timezone.now()
        job.save(update_fields=['status', 'error', 'finished_at'])
    return {'ok': job.status in ('success', 'partial'), 'status': job.status,
            'ok_count': job.ok_count, 'failed_count': job.failed_count}


@shared_task(name='serverops.chat_reply')
def run_chat_reply(message_id):
    """生成一条问答回复。message_id 指向那条 status='pending' 的 assistant 行。

    模型不可用/超时/返回空串，一律写成 ok=False + 可读 error 落在同一条记录上，
    页面上直接显示原因——不能让它一直转圈，也不能假装成功。
    """
    from serverops.models import ChatMessage
    from serverops.services import chat

    msg = ChatMessage.objects.filter(pk=message_id).first()
    if not msg:
        logger.warning('serverops 问答消息不存在: %s', message_id)
        return {'ok': False, 'error': '消息不存在'}

    prior = list(ChatMessage.objects.filter(session=msg.session, id__lt=msg.id)
                 .order_by('id'))
    question = ''
    history = prior
    for m in reversed(prior):
        if m.role == 'user':
            question = m.content or ''
            history = prior[:prior.index(m)]
            break

    res = chat.ask(question, os_type=msg.os_type, host=msg.host, history=history)
    msg.content = res.get('text') or ''
    msg.ok = bool(res.get('ok'))
    msg.error = (res.get('error') or '')[:2000]
    msg.model = (res.get('model') or '')[:128]
    msg.latency_ms = int(res.get('latency_ms') or 0)
    msg.status = 'done' if msg.ok else 'failed'
    msg.save(update_fields=['content', 'ok', 'error', 'model', 'latency_ms', 'status'])
    return {'ok': msg.ok, 'error': msg.error}
