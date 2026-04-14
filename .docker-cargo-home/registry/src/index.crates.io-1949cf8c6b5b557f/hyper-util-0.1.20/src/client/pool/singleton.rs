//! Singleton pools
//!
//! This ensures that only one active connection is made.
//!
//! The singleton pool wraps a `MakeService<T, Req>` so that it only produces a
//! single `Service<Req>`. It bundles all concurrent calls to it, so that only
//! one connection is made. All calls to the singleton will return a clone of
//! the inner service once established.
//!
//! This fits the HTTP/2 case well.
//!
//! ## Example
//!
//! ```rust,ignore
//! let mut pool = Singleton::new(some_make_svc);
//!
//! let svc1 = pool.call(some_dst).await?;
//!
//! let svc2 = pool.call(some_dst).await?;
//! // svc1 == svc2
//! ```

use std::sync::{Arc, Mutex};
use std::task::{self, Poll};

use tokio::sync::oneshot;
use tower_service::Service;

use self::internal::{DitchGuard, SingletonError, SingletonFuture, State};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[cfg(docsrs)]
pub use self::internal::Singled;

/// A singleton pool over an inner service.
///
/// The singleton wraps an inner service maker, bundling all calls to ensure
/// only one service is created. Once made, it returns clones of the made
/// service.
#[derive(Debug)]
pub struct Singleton<M, Dst>
where
    M: Service<Dst>,
{
    mk_svc: M,
    state: Arc<Mutex<State<M::Response>>>,
}

impl<M, Target> Singleton<M, Target>
where
    M: Service<Target>,
    M::Response: Clone,
{
    /// Create a new singleton pool over an inner make service.
    pub fn new(mk_svc: M) -> Self {
        Singleton {
            mk_svc,
            state: Arc::new(Mutex::new(State::Empty)),
        }
    }

    // pub fn clear? cancel?

    /// Retains the inner made service if specified by the predicate.
    pub fn retain<F>(&mut self, mut predicate: F)
    where
        F: FnMut(&mut M::Response) -> bool,
    {
        let mut locked = self.state.lock().unwrap();
        match *locked {
            State::Empty => {}
            State::Making(..) => {}
            State::Made(ref mut svc) => {
                if !predicate(svc) {
                    *locked = State::Empty;
                }
            }
        }
    }

    /// Returns whether this singleton pool is empty.
    ///
    /// If this pool has created a shared instance, or is currently in the
    /// process of creating one, this returns false.
    pub fn is_empty(&self) -> bool {
        matches!(*self.state.lock().unwrap(), State::Empty)
    }
}

impl<M, Target> Service<Target> for Singleton<M, Target>
where
    M: Service<Target>,
    M::Response: Clone,
    M::Error: Into<BoxError>,
{
    type Response = internal::Singled<M::Response>;
    type Error = SingletonError;
    type Future = SingletonFuture<M::Future, M::Response>;

    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        if let State::Empty = *self.state.lock().unwrap() {
            return self
                .mk_svc
                .poll_ready(cx)
                .map_err(|e| SingletonError(e.into()));
        }
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, dst: Target) -> Self::Future {
        let mut locked = self.state.lock().unwrap();
        match *locked {
            State::Empty => {
                let fut = self.mk_svc.call(dst);
                *locked = State::Making(Vec::new());
                SingletonFuture::Driving {
                    future: fut,
                    singleton: DitchGuard(Arc::downgrade(&self.state)),
                }
            }
            State::Making(ref mut waiters) => {
                let (tx, rx) = oneshot::channel();
                waiters.push(tx);
                SingletonFuture::Waiting {
                    rx,
                    state: Arc::downgrade(&self.state),
                }
            }
            State::Made(ref svc) => SingletonFuture::Made {
                svc: Some(svc.clone()),
                state: Arc::downgrade(&self.state),
            },
        }
    }
}

impl<M, Target> Clone for Singleton<M, Target>
where
    M: Service<Target> + Clone,
{
    fn clone(&self) -> Self {
        Self {
            mk_svc: self.mk_svc.clone(),
            state: self.state.clone(),
        }
    }
}

// Holds some "pub" items that otherwise shouldn't be public.
mod internal {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::{Mutex, Weak};
    use std::task::{self, ready, Poll};

    use pin_project_lite::pin_project;
    use tokio::sync::oneshot;
    use tower_service::Service;

    use super::BoxError;

    pin_project! {
        #[project = SingletonFutureProj]
        pub enum SingletonFuture<F, S> {
            Driving {
                #[pin]
                future: F,
                singleton: DitchGuard<S>,
            },
            Waiting {
                rx: oneshot::Receiver<S>,
                state: Weak<Mutex<State<S>>>,
            },
            Made {
                svc: Option<S>,
                state: Weak<Mutex<State<S>>>,
            },
        }
    }

    // XXX: pub because of the enum SingletonFuture
    #[derive(Debug)]
    pub enum State<S> {
        Empty,
        Making(Vec<oneshot::Sender<S>>),
        Made(S),
    }

    // XXX: pub because of the enum SingletonFuture
    pub struct DitchGuard<S>(pub(super) Weak<Mutex<State<S>>>);

    /// A cached service returned from a [`Singleton`].
    ///
    /// Implements `Service` by delegating to the inner service. If
    /// `poll_ready` returns an error, this will clear the cache in the related
    /// `Singleton`.
    ///
    /// [`Singleton`]: super::Singleton
    ///
    /// # Unnameable
    ///
    /// This type is normally unnameable, forbidding naming of the type within
    /// code. The type is exposed in the documentation to show which methods
    /// can be publicly called.
    #[derive(Debug)]
    pub struct Singled<S> {
        inner: S,
        state: Weak<Mutex<State<S>>>,
    }

    impl<F, S, E> Future for SingletonFuture<F, S>
    where
        F: Future<Output = Result<S, E>>,
        E: Into<BoxError>,
        S: Clone,
    {
        type Output = Result<Singled<S>, SingletonError>;

        fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
            match self.project() {
                SingletonFutureProj::Driving { future, singleton } => {
                    match ready!(future.poll(cx)) {
                        Ok(svc) => {
                            if let Some(state) = singleton.0.upgrade() {
                                let mut locked = state.lock().unwrap();
                                match std::mem::replace(&mut *locked, State::Made(svc.clone())) {
                                    State::Making(waiters) => {
                                        for tx in waiters {
                                            let _ = tx.send(svc.clone());
                                        }
                                    }
                                    State::Empty | State::Made(_) => {
                                        // shouldn't happen!
                                        unreachable!()
                                    }
                                }
                            }
                            // take out of the DitchGuard so it doesn't treat as "ditched"
                            let state = std::mem::replace(&mut singleton.0, Weak::new());
                            Poll::Ready(Ok(Singled::new(svc, state)))
                        }
                        Err(e) => {
                            if let Some(state) = singleton.0.upgrade() {
                                let mut locked = state.lock().unwrap();
                                singleton.0 = Weak::new();
                                *locked = State::Empty;
                            }
                            Poll::Ready(Err(SingletonError(e.into())))
                        }
                    }
                }
                SingletonFutureProj::Waiting { rx, state } => match ready!(Pin::new(rx).poll(cx)) {
                    Ok(svc) => Poll::Ready(Ok(Singled::new(svc, state.clone()))),
                    Err(_canceled) => Poll::Ready(Err(SingletonError(Canceled.into()))),
                },
                SingletonFutureProj::Made { svc, state } => {
                    Poll::Ready(Ok(Singled::new(svc.take().unwrap(), state.clone())))
                }
            }
        }
    }

    impl<S> Drop for DitchGuard<S> {
        fn drop(&mut self) {
            if let Some(state) = self.0.upgrade() {
                if let Ok(mut locked) = state.lock() {
                    *locked = State::Empty;
                }
            }
        }
    }

    impl<S> Singled<S> {
        fn new(inner: S, state: Weak<Mutex<State<S>>>) -> Self {
            Singled { inner, state }
        }
    }

    impl<S, Req> Service<Req> for Singled<S>
    where
        S: Service<Req>,
    {
        type Response = S::Response;
        type Error = S::Error;
        type Future = S::Future;

        fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
            // We notice if the cached service dies, and clear the singleton cache.
            match self.inner.poll_ready(cx) {
                Poll::Ready(Err(err)) => {
                    if let Some(state) = self.state.upgrade() {
                        *state.lock().unwrap() = State::Empty;
                    }
                    Poll::Ready(Err(err))
                }
                other => other,
            }
        }

        fn call(&mut self, req: Req) -> Self::Future {
            self.inner.call(req)
        }
    }

    // An opaque error type. By not exposing the type, nor being specifically
    // Box<dyn Error>, we can _change_ the type once we no longer need the Canceled
    // error type. This will be possible with the refactor to baton passing.
    #[derive(Debug)]
    pub struct SingletonError(pub(super) BoxError);

    impl std::fmt::Display for SingletonError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("singleton connection error")
        }
    }

    impl std::error::Error for SingletonError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&*self.0)
        }
    }

    #[derive(Debug)]
    struct Canceled;

    impl std::fmt::Display for Canceled {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("singleton connection canceled")
        }
    }

    impl std::error::Error for Canceled {}
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::pin::Pin;
    use std::task::Poll;

    use tower_service::Service;

    use super::Singleton;

    #[tokio::test]
    async fn first_call_drives_subsequent_wait() {
        let (mock_svc, mut handle) = tower_test::mock::pair::<(), &'static str>();

        let mut singleton = Singleton::new(mock_svc);

        handle.allow(1);
        std::future::poll_fn(|cx| singleton.poll_ready(cx))
            .await
            .unwrap();
        // First call: should go into Driving
        let fut1 = singleton.call(());
        // Second call: should go into Waiting
        let fut2 = singleton.call(());

        // Expect exactly one request to the inner service
        let ((), send_response) = handle.next_request().await.unwrap();
        send_response.send_response("svc");

        // Both futures should resolve to the same value
        fut1.await.unwrap();
        fut2.await.unwrap();
    }

    #[tokio::test]
    async fn made_state_returns_immediately() {
        let (mock_svc, mut handle) = tower_test::mock::pair::<(), &'static str>();
        let mut singleton = Singleton::new(mock_svc);

        handle.allow(1);
        std::future::poll_fn(|cx| singleton.poll_ready(cx))
            .await
            .unwrap();
        // Drive first call to completion
        let fut1 = singleton.call(());
        let ((), send_response) = handle.next_request().await.unwrap();
        send_response.send_response("svc");
        fut1.await.unwrap();

        // Second call should not hit inner service
        singleton.call(()).await.unwrap();
    }

    #[tokio::test]
    async fn cached_service_poll_ready_error_clears_singleton() {
        // Outer mock returns an inner mock service
        let (outer, mut outer_handle) =
            tower_test::mock::pair::<(), tower_test::mock::Mock<(), &'static str>>();
        let mut singleton = Singleton::new(outer);

        // Allow the singleton to be made
        outer_handle.allow(2);
        std::future::poll_fn(|cx| singleton.poll_ready(cx))
            .await
            .unwrap();

        // First call produces an inner mock service
        let fut1 = singleton.call(());
        let ((), send_inner) = outer_handle.next_request().await.unwrap();
        let (inner, mut inner_handle) = tower_test::mock::pair::<(), &'static str>();
        send_inner.send_response(inner);
        let mut cached = fut1.await.unwrap();

        // Now: allow readiness on the inner mock, then inject error
        inner_handle.allow(1);

        // Inject error so next poll_ready fails
        inner_handle.send_error(std::io::Error::new(
            std::io::ErrorKind::Other,
            "cached poll_ready failed",
        ));

        // Drive poll_ready on cached service
        let err = std::future::poll_fn(|cx| cached.poll_ready(cx))
            .await
            .err()
            .expect("expected poll_ready error");
        assert_eq!(err.to_string(), "cached poll_ready failed");

        // After error, the singleton should be cleared, so a new call drives outer again
        outer_handle.allow(1);
        std::future::poll_fn(|cx| singleton.poll_ready(cx))
            .await
            .unwrap();
        let fut2 = singleton.call(());
        let ((), send_inner2) = outer_handle.next_request().await.unwrap();
        let (inner2, mut inner_handle2) = tower_test::mock::pair::<(), &'static str>();
        send_inner2.send_response(inner2);
        let mut cached2 = fut2.await.unwrap();

        // The new cached service should still work
        inner_handle2.allow(1);
        std::future::poll_fn(|cx| cached2.poll_ready(cx))
            .await
            .expect("expected poll_ready");
        let cfut2 = cached2.call(());
        let ((), send_cached2) = inner_handle2.next_request().await.unwrap();
        send_cached2.send_response("svc2");
        cfut2.await.unwrap();
    }

    #[tokio::test]
    async fn cancel_waiter_does_not_affect_others() {
        let (mock_svc, mut handle) = tower_test::mock::pair::<(), &'static str>();
        let mut singleton = Singleton::new(mock_svc);

        std::future::poll_fn(|cx| singleton.poll_ready(cx))
            .await
            .unwrap();
        let fut1 = singleton.call(());
        let fut2 = singleton.call(());
        drop(fut2); // cancel one waiter

        let ((), send_response) = handle.next_request().await.unwrap();
        send_response.send_response("svc");

        fut1.await.unwrap();
    }

    // TODO: this should be able to be improved with a cooperative baton refactor
    #[tokio::test]
    async fn cancel_driver_cancels_all() {
        let (mock_svc, mut handle) = tower_test::mock::pair::<(), &'static str>();
        let mut singleton = Singleton::new(mock_svc);

        std::future::poll_fn(|cx| singleton.poll_ready(cx))
            .await
            .unwrap();
        let mut fut1 = singleton.call(());
        let fut2 = singleton.call(());

        // poll driver just once, and then drop
        std::future::poll_fn(move |cx| {
            let _ = Pin::new(&mut fut1).poll(cx);
            Poll::Ready(())
        })
        .await;

        let ((), send_response) = handle.next_request().await.unwrap();
        send_response.send_response("svc");

        assert_eq!(
            fut2.await.unwrap_err().0.to_string(),
            "singleton connection canceled"
        );
    }
}
