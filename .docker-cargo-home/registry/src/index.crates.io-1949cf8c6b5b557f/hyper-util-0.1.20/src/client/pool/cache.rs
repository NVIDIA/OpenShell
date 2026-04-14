//! A cache of services
//!
//! The cache is a single list of cached services, bundled with a `MakeService`.
//! Calling the cache returns either an existing service, or makes a new one.
//! The returned `impl Service` can be used to send requests, and when dropped,
//! it will try to be returned back to the cache.

pub use self::internal::builder;

#[cfg(docsrs)]
pub use self::internal::Builder;
#[cfg(docsrs)]
pub use self::internal::Cache;
#[cfg(docsrs)]
pub use self::internal::Cached;

// For now, nothing else in this module is nameable. We can always make things
// more public, but we can't change type shapes (generics) once things are
// public.
mod internal {
    use std::fmt;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex, Weak};
    use std::task::{self, ready, Poll};

    use futures_util::future;
    use tokio::sync::oneshot;
    use tower_service::Service;

    use super::events;

    /// Start a builder to construct a `Cache` pool.
    pub fn builder() -> Builder<events::Ignore> {
        Builder {
            events: events::Ignore,
        }
    }

    /// A cache pool of services from the inner make service.
    ///
    /// Created with [`builder()`].
    ///
    /// # Unnameable
    ///
    /// This type is normally unnameable, forbidding naming of the type within
    /// code. The type is exposed in the documentation to show which methods
    /// can be publicly called.
    #[derive(Debug)]
    pub struct Cache<M, Dst, Ev>
    where
        M: Service<Dst>,
    {
        connector: M,
        shared: Arc<Mutex<Shared<M::Response>>>,
        events: Ev,
    }

    /// A builder to configure a `Cache`.
    ///
    /// # Unnameable
    ///
    /// This type is normally unnameable, forbidding naming of the type within
    /// code. The type is exposed in the documentation to show which methods
    /// can be publicly called.
    #[derive(Debug)]
    pub struct Builder<Ev> {
        events: Ev,
    }

    /// A cached service returned from a [`Cache`].
    ///
    /// Implements `Service` by delegating to the inner service. Once dropped,
    /// tries to reinsert into the `Cache`.
    ///
    /// # Unnameable
    ///
    /// This type is normally unnameable, forbidding naming of the type within
    /// code. The type is exposed in the documentation to show which methods
    /// can be publicly called.
    pub struct Cached<S> {
        is_closed: bool,
        inner: Option<S>,
        shared: Weak<Mutex<Shared<S>>>,
        // todo: on_idle
    }

    pub enum CacheFuture<M, Dst, Ev>
    where
        M: Service<Dst>,
    {
        Racing {
            shared: Arc<Mutex<Shared<M::Response>>>,
            select: future::Select<oneshot::Receiver<M::Response>, M::Future>,
            events: Ev,
        },
        Connecting {
            // TODO: could be Weak even here...
            shared: Arc<Mutex<Shared<M::Response>>>,
            future: M::Future,
        },
        Cached {
            svc: Option<Cached<M::Response>>,
        },
    }

    // shouldn't be pub
    #[derive(Debug)]
    pub struct Shared<S> {
        services: Vec<S>,
        waiters: Vec<oneshot::Sender<S>>,
    }

    // impl Builder

    impl<Ev> Builder<Ev> {
        /// Provide a `Future` executor to be used by the `Cache`.
        ///
        /// The executor is used handle some optional background tasks that
        /// can improve the behavior of the cache, such as reducing connection
        /// thrashing when a race is won. If not configured with an executor,
        /// the default behavior is to ignore any of these optional background
        /// tasks.
        ///
        /// The executor should implmenent [`hyper::rt::Executor`].
        ///
        /// # Example
        ///
        /// ```rust
        /// # #[cfg(feature = "tokio")]
        /// # fn run() {
        /// let builder = hyper_util::client::pool::cache::builder()
        ///     .executor(hyper_util::rt::TokioExecutor::new());
        /// # }
        /// ```
        pub fn executor<E>(self, exec: E) -> Builder<events::WithExecutor<E>> {
            Builder {
                events: events::WithExecutor(exec),
            }
        }

        /// Build a `Cache` pool around the `connector`.
        pub fn build<M, Dst>(self, connector: M) -> Cache<M, Dst, Ev>
        where
            M: Service<Dst>,
        {
            Cache {
                connector,
                events: self.events,
                shared: Arc::new(Mutex::new(Shared {
                    services: Vec::new(),
                    waiters: Vec::new(),
                })),
            }
        }
    }

    // impl Cache

    impl<M, Dst, Ev> Cache<M, Dst, Ev>
    where
        M: Service<Dst>,
    {
        /// Retain all cached services indicated by the predicate.
        pub fn retain<F>(&mut self, predicate: F)
        where
            F: FnMut(&mut M::Response) -> bool,
        {
            self.shared.lock().unwrap().services.retain_mut(predicate);
        }

        /// Check whether this cache has no cached services.
        pub fn is_empty(&self) -> bool {
            self.shared.lock().unwrap().services.is_empty()
        }
    }

    impl<M, Dst, Ev> Service<Dst> for Cache<M, Dst, Ev>
    where
        M: Service<Dst>,
        M::Future: Unpin,
        M::Response: Unpin,
        Ev: events::Events<BackgroundConnect<M::Future, M::Response>> + Clone + Unpin,
    {
        type Response = Cached<M::Response>;
        type Error = M::Error;
        type Future = CacheFuture<M, Dst, Ev>;

        fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
            if !self.shared.lock().unwrap().services.is_empty() {
                Poll::Ready(Ok(()))
            } else {
                self.connector.poll_ready(cx)
            }
        }

        fn call(&mut self, target: Dst) -> Self::Future {
            // 1. If already cached, easy!
            let waiter = {
                let mut locked = self.shared.lock().unwrap();
                if let Some(found) = locked.take() {
                    return CacheFuture::Cached {
                        svc: Some(Cached::new(found, Arc::downgrade(&self.shared))),
                    };
                }

                let (tx, rx) = oneshot::channel();
                locked.waiters.push(tx);
                rx
            };

            // 2. Otherwise, we start a new connect, and also listen for
            //    any newly idle.
            CacheFuture::Racing {
                shared: self.shared.clone(),
                select: future::select(waiter, self.connector.call(target)),
                events: self.events.clone(),
            }
        }
    }

    impl<M, Dst, Ev> Clone for Cache<M, Dst, Ev>
    where
        M: Service<Dst> + Clone,
        Ev: Clone,
    {
        fn clone(&self) -> Self {
            Self {
                connector: self.connector.clone(),
                events: self.events.clone(),
                shared: self.shared.clone(),
            }
        }
    }

    impl<M, Dst, Ev> Future for CacheFuture<M, Dst, Ev>
    where
        M: Service<Dst>,
        M::Future: Unpin,
        M::Response: Unpin,
        Ev: events::Events<BackgroundConnect<M::Future, M::Response>> + Unpin,
    {
        type Output = Result<Cached<M::Response>, M::Error>;

        fn poll(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
            loop {
                match &mut *self.as_mut() {
                    CacheFuture::Racing {
                        shared,
                        select,
                        events,
                    } => {
                        match ready!(Pin::new(select).poll(cx)) {
                            future::Either::Left((Err(_pool_closed), connecting)) => {
                                // pool was dropped, so we'll never get it from a waiter,
                                // but if this future still exists, then the user still
                                // wants a connection. just wait for the connecting
                                *self = CacheFuture::Connecting {
                                    shared: shared.clone(),
                                    future: connecting,
                                };
                            }
                            future::Either::Left((Ok(pool_got), connecting)) => {
                                events.on_race_lost(BackgroundConnect {
                                    future: connecting,
                                    shared: Arc::downgrade(&shared),
                                });
                                return Poll::Ready(Ok(Cached::new(
                                    pool_got,
                                    Arc::downgrade(&shared),
                                )));
                            }
                            future::Either::Right((connected, _waiter)) => {
                                let inner = connected?;
                                return Poll::Ready(Ok(Cached::new(
                                    inner,
                                    Arc::downgrade(&shared),
                                )));
                            }
                        }
                    }
                    CacheFuture::Connecting { shared, future } => {
                        let inner = ready!(Pin::new(future).poll(cx))?;
                        return Poll::Ready(Ok(Cached::new(inner, Arc::downgrade(&shared))));
                    }
                    CacheFuture::Cached { svc } => {
                        return Poll::Ready(Ok(svc.take().unwrap()));
                    }
                }
            }
        }
    }

    // impl Cached

    impl<S> Cached<S> {
        fn new(inner: S, shared: Weak<Mutex<Shared<S>>>) -> Self {
            Cached {
                is_closed: false,
                inner: Some(inner),
                shared,
            }
        }

        // TODO: inner()? looks like `tower` likes `get_ref()` and `get_mut()`.

        /// Get a reference to the inner service.
        pub fn inner(&self) -> &S {
            self.inner.as_ref().expect("inner only taken in drop")
        }

        /// Get a mutable reference to the inner service.
        pub fn inner_mut(&mut self) -> &mut S {
            self.inner.as_mut().expect("inner only taken in drop")
        }
    }

    impl<S, Req> Service<Req> for Cached<S>
    where
        S: Service<Req>,
    {
        type Response = S::Response;
        type Error = S::Error;
        type Future = S::Future;

        fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
            self.inner.as_mut().unwrap().poll_ready(cx).map_err(|err| {
                self.is_closed = true;
                err
            })
        }

        fn call(&mut self, req: Req) -> Self::Future {
            self.inner.as_mut().unwrap().call(req)
        }
    }

    impl<S> Drop for Cached<S> {
        fn drop(&mut self) {
            if self.is_closed {
                return;
            }
            if let Some(value) = self.inner.take() {
                if let Some(shared) = self.shared.upgrade() {
                    if let Ok(mut shared) = shared.lock() {
                        shared.put(value);
                    }
                }
            }
        }
    }

    impl<S: fmt::Debug> fmt::Debug for Cached<S> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_tuple("Cached")
                .field(self.inner.as_ref().unwrap())
                .finish()
        }
    }

    // impl Shared

    impl<V> Shared<V> {
        fn put(&mut self, val: V) {
            let mut val = Some(val);
            while let Some(tx) = self.waiters.pop() {
                if !tx.is_closed() {
                    match tx.send(val.take().unwrap()) {
                        Ok(()) => break,
                        Err(v) => {
                            val = Some(v);
                        }
                    }
                }
            }

            if let Some(val) = val {
                self.services.push(val);
            }
        }

        fn take(&mut self) -> Option<V> {
            // TODO: take in a loop
            self.services.pop()
        }
    }

    pub struct BackgroundConnect<CF, S> {
        future: CF,
        shared: Weak<Mutex<Shared<S>>>,
    }

    impl<CF, S, E> Future for BackgroundConnect<CF, S>
    where
        CF: Future<Output = Result<S, E>> + Unpin,
    {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
            match ready!(Pin::new(&mut self.future).poll(cx)) {
                Ok(svc) => {
                    if let Some(shared) = self.shared.upgrade() {
                        if let Ok(mut locked) = shared.lock() {
                            locked.put(svc);
                        }
                    }
                    Poll::Ready(())
                }
                Err(_e) => Poll::Ready(()),
            }
        }
    }
}

mod events {
    #[derive(Clone, Debug)]
    #[non_exhaustive]
    pub struct Ignore;

    #[derive(Clone, Debug)]
    pub struct WithExecutor<E>(pub(super) E);

    pub trait Events<CF> {
        fn on_race_lost(&self, fut: CF);
    }

    impl<CF> Events<CF> for Ignore {
        fn on_race_lost(&self, _fut: CF) {}
    }

    impl<E, CF> Events<CF> for WithExecutor<E>
    where
        E: hyper::rt::Executor<CF>,
    {
        fn on_race_lost(&self, fut: CF) {
            self.0.execute(fut);
        }
    }
}

#[cfg(test)]
mod tests {
    use futures_util::future;
    use tower_service::Service;
    use tower_test::assert_request_eq;

    #[tokio::test]
    async fn test_makes_svc_when_empty() {
        let (mock, mut handle) = tower_test::mock::pair();
        let mut cache = super::builder().build(mock);
        handle.allow(1);

        std::future::poll_fn(|cx| cache.poll_ready(cx))
            .await
            .unwrap();

        let f = cache.call(1);

        future::join(f, async move {
            assert_request_eq!(handle, 1).send_response("one");
        })
        .await
        .0
        .expect("call");
    }

    #[tokio::test]
    async fn test_reuses_after_idle() {
        let (mock, mut handle) = tower_test::mock::pair();
        let mut cache = super::builder().build(mock);

        // only 1 connection should ever be made
        handle.allow(1);

        std::future::poll_fn(|cx| cache.poll_ready(cx))
            .await
            .unwrap();
        let f = cache.call(1);
        let cached = future::join(f, async {
            assert_request_eq!(handle, 1).send_response("one");
        })
        .await
        .0
        .expect("call");
        drop(cached);

        std::future::poll_fn(|cx| cache.poll_ready(cx))
            .await
            .unwrap();
        let f = cache.call(1);
        let cached = f.await.expect("call");
        drop(cached);
    }
}
