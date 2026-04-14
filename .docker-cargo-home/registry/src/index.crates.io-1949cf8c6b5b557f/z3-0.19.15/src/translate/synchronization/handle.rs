use crate::translate::Translate;
use crate::{Config, Context};
use std::fmt::{Debug, Formatter};
use std::sync::Mutex;

/// A [`Send`] and [`Sync`] wrapper for Z3 structures associated with a [`Context`].
///
/// This wrapper
/// takes in a Z3 type (or a user-defined type that uses Z3 types) and translates its contents
/// into a private "singleton" [`Context`]. Since this [`Context`] is unused elsewhere, it is safe
/// to [`Send`] it and its contents to other threads AND to have [`Sync`] accesses across threads.
/// The safety of the [`Send`] impl is upheld by construction, as all data associated with the inner
/// [`Context`] is guaranteed to be moved with it.
/// The safety of the [`Sync`] impl is upheld through an inner [`Mutex`].
///
/// Inner data can only be accessed through [`Synchronized::recover`], which translates the contents
/// for the given [`Context`].
///
/// # Performance
///
/// Initializing this type (usually done through
/// [`PrepareSynchronized::synchronized`](crate::PrepareSynchronized::synchronized))
/// will allocate
/// a new [`Context`] and [`Translate`] the provided `T` into it. This involves a non-zero amount of
/// overhead; if you are creating thousands of [`Synchronized`], you will see a performance impact.
///
/// If you need to move/reference a collection of data between threads, consider putting it in
/// a [`Vec`], which also implements [`PrepareSynchronized`](crate::PrepareSynchronized), and will
/// only create one [`Context`]. You can also implement [`Translate`] on your own types, which
/// will then inherit from a blanket impl of [`PrepareSynchronized`](crate::PrepareSynchronized)
/// for [`Translate`].
///
/// Note that this will only alleviate the overhead of
/// allocating many [`Context`]s. There is still some unavoidable overhead:
/// * A [`Context`] must  be allocated.
/// * Your `T` must be [`Translate`]'d into the [`Context`].
/// * The data inside [`Synchronized`] must be [`Translate`]'d out to be used.
///
/// Z3 translation scales in proportion to the complexity of the statement; if you use this with
/// some very complex set of formulas, expect it to take longer.
///
/// # See also:
///
/// - [`PrepareSendable`](crate::PrepareSynchronized)
/// - [`Translate`]
pub struct Synchronized<T>(pub(super) Mutex<T>);

impl<T: Debug> Debug for Synchronized<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let inner = self.0.lock().unwrap();
        f.debug_tuple("Synchronized").field(&inner).finish()
    }
}
impl<T: Translate> Synchronized<T> {
    /// Creates a new handle that is [`Send`] and [`Sync`], allowing for easily moving
    /// your z3 structs to other threads.
    /// Data passed in here is `translate`'d into a one-off `Context` and is then put in a `Mutex`,
    /// allowing it to be moved and referenced across threads
    /// soundly. None of this effects the original data.
    pub fn new(data: &T) -> Self {
        let ctx = Context::new(&Config::new());
        let data = data.translate(&ctx);
        Self(Mutex::new(data))
    }
}

impl<T: Translate> Synchronized<T> {
    /// Unwrap the `SendableHandle`, translate its contents for the given [`Context`]
    /// and return the inner data.
    pub fn recover(&self) -> T {
        let ctx = &Context::thread_local();
        self.0.lock().unwrap().translate(ctx)
    }
}

/// Cloning a [`Synchronized`] will create a new [`Context`] and translate the data into it.
/// This allows a handle to be easily sent to multiple threads without violating context
/// memory safety, at the expense of some extra cloning.
impl<T: Translate> Clone for Synchronized<T> {
    fn clone(&self) -> Self {
        let ctx = Context::new(&Config::new());
        let data = self.0.lock().unwrap().translate(&ctx);
        Self(Mutex::new(data))
    }
}

/// The [`Context`] inside is only used with the [`Translate`] inside, so
/// it is sound to [`Send`]
unsafe impl<T: Translate> Send for Synchronized<T> {}
/// The only method access to the [`Ast`](crate::ast::Ast) or [`Context`] is guarded
/// by a [`Mutex`], so it is sound to [`Sync`]
unsafe impl<T: Translate> Sync for Synchronized<T> {}
