//! Bounded lifecycle scheduling with ephemeral per-sandbox workers.

use crate::error::{Error, Result};
use sandboxd_protocol::SandboxId;
use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};
use tokio::{
    sync::{Mutex, Notify, Semaphore, oneshot},
    time::{Duration, timeout},
};

type JobFuture = Pin<Box<dyn Future<Output = Result<()>> + Send>>;
struct Job {
    operation: JobFuture,
    reply: oneshot::Sender<Result<()>>,
}
struct KeyQueue {
    jobs: VecDeque<Job>,
    worker: bool,
    active: bool,
}
struct Inner {
    queues: Mutex<HashMap<SandboxId, KeyQueue>>,
    permits: Arc<Semaphore>,
    per_key: usize,
    max_in_flight: usize,
    admitted: AtomicUsize,
    pending: AtomicUsize,
    closed: AtomicBool,
    drained: Notify,
}

#[derive(Clone)]
pub struct RuntimeQueue {
    inner: Arc<Inner>,
}

impl RuntimeQueue {
    pub fn new(max_concurrent: usize, per_sandbox_capacity: usize) -> Result<Self> {
        if max_concurrent == 0
            || max_concurrent > 100_000
            || per_sandbox_capacity == 0
            || per_sandbox_capacity > 16
        {
            return Err(Error::Config(
                "runtime queue bounds must be finite and positive",
            ));
        }
        let pending = max_concurrent
            .checked_mul(per_sandbox_capacity)
            .ok_or(Error::Config("runtime queue bound overflow"))?;
        let max_in_flight = pending
            .checked_add(max_concurrent)
            .ok_or(Error::Config("runtime queue bound overflow"))?;
        Ok(Self {
            inner: Arc::new(Inner {
                queues: Mutex::new(HashMap::new()),
                permits: Arc::new(Semaphore::new(max_concurrent)),
                per_key: per_sandbox_capacity,
                max_in_flight,
                admitted: AtomicUsize::new(0),
                pending: AtomicUsize::new(0),
                closed: AtomicBool::new(false),
                drained: Notify::new(),
            }),
        })
    }

    /// Admit one effect. Dropping its receiver never cancels the effect.
    pub async fn submit<F>(
        &self,
        sandbox: SandboxId,
        operation: F,
    ) -> Result<oneshot::Receiver<Result<()>>>
    where
        F: Future<Output = Result<()>> + Send + 'static,
    {
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(Error::State);
        }
        let (reply, receiver) = oneshot::channel();
        let spawn_worker;
        {
            let mut queues = self.inner.queues.lock().await;
            if self.inner.closed.load(Ordering::Acquire)
                || self.inner.admitted.load(Ordering::Relaxed) >= self.inner.max_in_flight
            {
                return Err(if self.inner.closed.load(Ordering::Acquire) {
                    Error::State
                } else {
                    queue_full()
                });
            }
            let queue = queues.entry(sandbox.clone()).or_insert_with(|| KeyQueue {
                jobs: VecDeque::new(),
                worker: false,
                active: false,
            });
            if queue.jobs.len() + usize::from(queue.active) >= self.inner.per_key {
                return Err(queue_full());
            }
            queue.jobs.push_back(Job {
                operation: Box::pin(operation),
                reply,
            });
            spawn_worker = !queue.worker;
            queue.worker = true;
            self.inner.admitted.fetch_add(1, Ordering::Relaxed);
            self.inner.pending.fetch_add(1, Ordering::Relaxed);
        }
        if spawn_worker {
            let inner = Arc::clone(&self.inner);
            tokio::spawn(async move { run_key(inner, sandbox).await });
        }
        Ok(receiver)
    }

    /// Rejects new effects and waits for all already-admitted effects. A
    /// timeout returns an error without cancelling or killing a live VM.
    pub async fn close_and_drain(&self, wait: Duration) -> Result<()> {
        self.inner.closed.store(true, Ordering::Release);
        if self.inner.admitted.load(Ordering::Acquire) == 0 {
            return Ok(());
        }
        timeout(wait, async {
            loop {
                let notified = self.inner.drained.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if self.inner.admitted.load(Ordering::Acquire) == 0 {
                    return;
                }
                notified.await;
            }
        })
        .await
        .map_err(|_| Error::State)
    }

    pub fn accepted_jobs(&self) -> usize {
        self.inner.admitted.load(Ordering::Acquire)
    }

    #[cfg(test)]
    async fn key_count(&self) -> usize {
        self.inner.queues.lock().await.len()
    }
}

async fn run_key(inner: Arc<Inner>, sandbox: SandboxId) {
    loop {
        let job = {
            let mut queues = inner.queues.lock().await;
            let Some(queue) = queues.get_mut(&sandbox) else {
                return;
            };
            let job = queue.jobs.pop_front();
            if job.is_some() {
                queue.active = true;
            }
            if job.is_none() {
                queues.remove(&sandbox);
            }
            job
        };
        let Some(job) = job else { return };
        inner.pending.fetch_sub(1, Ordering::Relaxed);
        let result = match inner.permits.clone().acquire_owned().await {
            Ok(permit) => {
                // A panicking effect must not leak its slot or strand subsequent work.
                let result = tokio::spawn(job.operation)
                    .await
                    .unwrap_or(Err(Error::State));
                drop(permit);
                result
            }
            Err(_) => Err(Error::State),
        };
        let has_next = {
            let mut queues = inner.queues.lock().await;
            let next = if let Some(queue) = queues.get_mut(&sandbox) {
                queue.active = false;
                !queue.jobs.is_empty()
            } else {
                false
            };
            if !next {
                queues.remove(&sandbox);
            }
            next
        };
        inner.admitted.fetch_sub(1, Ordering::Release);
        let _ = job.reply.send(result);
        if inner.admitted.load(Ordering::Acquire) == 0 {
            inner.drained.notify_waiters();
        }
        tokio::task::yield_now().await;
        if !has_next {
            return;
        }
    }
}
fn queue_full() -> Error {
    Error::Api(sandboxd_protocol::ApiError::new(
        sandboxd_protocol::ErrorCode::QuotaExceeded,
        "runtime lifecycle queue is full",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::sync::{Barrier, Mutex};
    fn id(v: &str) -> SandboxId {
        SandboxId::new(v).expect("sandbox id")
    }

    #[tokio::test]
    async fn churn_removes_idle_keys() {
        let q = RuntimeQueue::new(2, 2).expect("bounds");
        for n in 0..128 {
            q.submit(id(&format!("s-{n}")), async { Ok(()) })
                .await
                .expect("admit")
                .await
                .expect("reply")
                .expect("effect");
        }
        tokio::task::yield_now().await;
        assert_eq!(q.key_count().await, 0);
    }
    #[tokio::test]
    async fn bounds_and_close_reject_new_work() {
        let q = RuntimeQueue::new(1, 2).expect("bounds");
        let barrier = Arc::new(Barrier::new(2));
        let hold = Arc::clone(&barrier);
        let first = q
            .submit(id("one"), async move {
                hold.wait().await;
                Ok(())
            })
            .await
            .expect("first");
        let _second = q.submit(id("one"), async { Ok(()) }).await.expect("second");
        assert!(q.submit(id("one"), async { Ok(()) }).await.is_err());
        assert!(q.close_and_drain(Duration::from_millis(1)).await.is_err());
        assert!(q.submit(id("two"), async { Ok(()) }).await.is_err());
        barrier.wait().await;
        assert!(q.close_and_drain(Duration::from_secs(1)).await.is_ok());
        first.await.expect("reply").expect("effect");
    }
    #[tokio::test]
    async fn different_keys_progress_fairly() {
        let q = RuntimeQueue::new(1, 4).expect("bounds");
        let order = Arc::new(Mutex::new(Vec::new()));
        let a = Arc::clone(&order);
        let first = q
            .submit(id("one"), async move {
                a.lock().await.push(1);
                Ok(())
            })
            .await
            .expect("first");
        let a = Arc::clone(&order);
        let _queued = q
            .submit(id("one"), async move {
                a.lock().await.push(2);
                Ok(())
            })
            .await
            .expect("queued");
        let b = Arc::clone(&order);
        let other = q
            .submit(id("two"), async move {
                b.lock().await.push(3);
                Ok(())
            })
            .await
            .expect("other");
        first.await.expect("reply").expect("effect");
        other.await.expect("reply").expect("effect");
        assert!(order.lock().await.contains(&3));
    }
    #[tokio::test]
    async fn dropped_reply_still_runs_effect() {
        let q = RuntimeQueue::new(1, 1).expect("bounds");
        let count = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&count);
        drop(
            q.submit(id("drop"), async move {
                c.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .await
            .expect("admit"),
        );
        for _ in 0..20 {
            if count.load(Ordering::SeqCst) == 1 {
                return;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn panicking_job_does_not_leak_capacity_or_strand_key() {
        let queue = RuntimeQueue::new(1, 1).expect("bounds");
        let result = queue
            .submit(id("panic"), async { panic!("attack fixture") })
            .await
            .expect("admission")
            .await
            .expect("reply");
        assert!(result.is_err());
        assert_eq!(queue.accepted_jobs(), 0);
        assert_eq!(queue.key_count().await, 0);
        queue
            .submit(id("panic"), async { Ok(()) })
            .await
            .expect("slot reused")
            .await
            .expect("reply")
            .expect("next effect");
        queue
            .close_and_drain(Duration::from_secs(1))
            .await
            .expect("drained");
    }
}
