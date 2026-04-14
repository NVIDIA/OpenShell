mod handle;

pub use crate::translate::synchronization::handle::Synchronized;
use crate::{Config, Context, Translate};
use std::sync::Mutex;

/// This trait allows a type to opt-in to multithreading through [`Synchronized`].
///
/// Instead of implementing this trait, users should prefer to implement [`Translate`]
/// to take advantage of its blanket implementation of [`PrepareSynchronized`].
///
/// # Usage
///
/// [`Synchronized`] handles can be _moved_ to another thread.
/// ```
/// use z3::ast::{Bool, Int};
/// use z3::{Context, PrepareSynchronized, Solver, Translate};
///
/// // Creating a Synchronized<BV> and moving it to another thread.
/// let bv = Bool::from_bool(true);
/// let sendable = bv.synchronized();
/// std::thread::spawn(move || {
///     let moved = sendable.recover();
///     assert_eq!(moved.as_bool(), Some(true));
/// }).join().expect("Thread panicked");
///```
///
/// [`Synchronized`] handles can hold anything that is [`Translate`], including [`Ast`](crate::ast::Ast)s,
/// [`Solver`](crate::Solver)s and [`Model`](crate::Model)s. This allows the pattern of defining
/// a set of [`Ast`](crate::ast::Ast)s and [`Solver`](crate::Solver)s in a main thread and
/// offloading the actual [`Solver::check`](crate::Solver::check) call to a worker thread,
/// with the eventual resulting model being moved back into the main thread.
///
///```
/// // Creating a Solver with some assertions, checking it from a thread,
/// // and moving the resulting model back out for inspection.
/// use z3::ast::{Ast, Bool};
/// use z3::{Context, PrepareSynchronized, Solver};
/// let bool = Bool::new_const("hello");
/// let sendable_solver = {
///     let solver = Solver::new();
///     solver.assert(&bool._eq(&Bool::from_bool(true)));
///     solver.synchronized()
/// };
/// let model = std::thread::spawn(move || {
///     let moved_solver = sendable_solver.recover();
///     moved_solver.check();
///     let model = moved_solver.get_model().unwrap();
///     model.synchronized()
/// }).join().expect("Thread panicked");
/// let model = model.recover();
/// assert_eq!(model.eval(&bool, true), Some(Bool::from_bool(true)));
///```
///
/// Consumers of this library may implement [`Translate`] for their types that use
/// Z3 structures, to directly enable their usage in multi-threaded scenarios.
///
///```
/// # use std::thread;
/// # use z3::ast::{Ast, Bool, Int};
/// # use z3::{Context, PrepareSynchronized, Solver, Translate};
/// // Implementing Translate for a struct containing a BitVector and
/// // an Int, and then creating a Synchronized from it and moving
/// // it to a thread
/// struct MyStruct {
///     bv: Bool,
///     int: Int,
/// }
///
/// unsafe impl Translate for MyStruct {
///     fn translate(&self, ctx: &Context) -> Self {
///         MyStruct {
///             bv: self.bv.translate(ctx),
///             int: self.int.translate(ctx),
///         }
///     }
/// }
///
/// let my_struct = MyStruct {
///     bv: Bool::from_bool(true),
///     int: Int::from_i64(42),
/// };
/// let sendable_struct = my_struct.synchronized();
/// thread::spawn(move || {
///     let moved = sendable_struct.recover();
///     assert_eq!(moved.bv.as_bool(), Some(true));
///     assert_eq!(moved.int.as_i64(), Some(42));
/// }).join().expect("Thread panicked");
/// ```
pub trait PrepareSynchronized {
    type Inner;

    /// Creates a thread-safe wrapper that is both [`Send`] and [`Sync`].
    ///
    /// See also:
    ///
    /// [`Synchronized`]
    fn synchronized(&self) -> Synchronized<Self::Inner>;
}

/// Special implementation directly constructing the handle to avoid unnecessary allocations
impl<T: Translate> PrepareSynchronized for &[T] {
    type Inner = Vec<T>;

    fn synchronized(&self) -> Synchronized<Self::Inner> {
        let ctx = Context::new(&Config::new());
        let data: Vec<T> = self.iter().map(|t| t.translate(&ctx)).collect();
        Synchronized(Mutex::new(data))
    }
}

/// All `Translate` types are `PrepareSendable`. Users should implement `Translate`
/// in order to use `PrepareSendable` for their types.
impl<T: Translate> PrepareSynchronized for T {
    type Inner = T;

    fn synchronized(&self) -> Synchronized<Self::Inner> {
        Synchronized::new(self)
    }
}

/// Test using standard threads
#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod thread_tests {
    use crate::Solver;
    use crate::ast::Bool;
    use crate::translate::synchronization::PrepareSynchronized;

    #[test]
    fn test_send() {
        let bv = Bool::from_bool(true);
        let sendable = bv.synchronized();
        std::thread::spawn(move || {
            let moved = sendable.recover();
            assert_eq!(moved.as_bool(), Some(true));
        })
        .join()
        .expect("uh oh");
    }

    #[test]
    fn test_send_vec() {
        let bv = vec![Bool::from_bool(true); 8];
        let sendable = bv.synchronized();
        std::thread::spawn(move || {
            let moved = sendable.recover();
            for x in moved {
                assert_eq!(x.as_bool(), Some(true));
            }
        })
        .join()
        .expect("uh oh");
    }

    #[test]
    fn test_round_trip() {
        let bool = Bool::new_const("hello");
        let sendable = bool.synchronized();
        let model = std::thread::spawn(move || {
            let moved = sendable.recover();
            let solver = Solver::new();
            solver.assert(moved);
            solver.check();
            let model = solver.get_model().unwrap();
            model.synchronized()
        })
        .join()
        .expect("uh oh");
        let model = model.recover();
        assert_eq!(model.eval(&bool, true), Some(Bool::from_bool(true)));
    }
}

#[cfg(test)]
mod rayon_tests {
    use crate::ast::Int;
    use crate::{PrepareSynchronized, Solver};
    use std::ops::Add;

    #[test]
    fn test_rayon() {
        use rayon::prelude::*;
        let int = Int::fresh_const("hello").add(2);
        let sendable = int.synchronized();
        (0..100).into_par_iter().for_each(|i| {
            let moved = sendable.recover();
            let solver = Solver::new();
            solver.assert(moved.eq(i));
            assert_eq!(solver.check(), crate::SatResult::Sat);
            let model = solver.get_model().unwrap();
            assert_eq!(model.eval(&moved, true).unwrap(), i);
        })
    }
}
