use std::ffi::{CStr, CString};
use z3_sys::*;

#[test]
fn smoketest() {
    unsafe {
        let cfg = Z3_mk_config().unwrap();
        let ctx = Z3_mk_context(cfg).unwrap();

        let str_x = CString::new("x").unwrap();
        let str_y = CString::new("y").unwrap();

        let sym_x = Z3_mk_string_symbol(ctx, str_x.as_ptr()).unwrap();
        let sym_y = Z3_mk_string_symbol(ctx, str_y.as_ptr()).unwrap();

        let int_sort = Z3_mk_int_sort(ctx).unwrap();

        let const_x = Z3_mk_const(ctx, sym_x, int_sort).unwrap();
        let const_y = Z3_mk_const(ctx, sym_y, int_sort).unwrap();
        let gt = Z3_mk_gt(ctx, const_x, const_y).unwrap();

        let solver = Z3_mk_simple_solver(ctx).unwrap();
        Z3_solver_assert(ctx, solver, gt);
        assert_eq!(Z3_solver_check(ctx, solver), Z3_L_TRUE);

        let model = Z3_solver_get_model(ctx, solver).unwrap();

        // Check that the string-value of the model is as expected
        let model_s = Z3_model_to_string(ctx, model);

        let model_str = CStr::from_ptr(model_s).to_str().unwrap();
        let model_elements = model_str.split_terminator('\n').collect::<Vec<_>>();
        assert_eq!(model_elements.len(), 2);

        // Grab the actual constant values out of the model
        let mut interp_x: Z3_ast = const_x;
        let mut interp_y: Z3_ast = const_y;
        assert!(Z3_model_eval(ctx, model, const_x, true, &mut interp_x));
        assert!(Z3_model_eval(ctx, model, const_y, true, &mut interp_y));

        let mut val_x: i32 = -5;
        let mut val_y: i32 = -5;
        assert!(Z3_get_numeral_int(ctx, interp_x, &mut val_x));
        assert!(Z3_get_numeral_int(ctx, interp_y, &mut val_y));
        assert!(val_x > val_y);

        Z3_del_context(ctx);
        Z3_del_config(cfg);
    }
}
