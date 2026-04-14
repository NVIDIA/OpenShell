use std::io;

use console::{Key, Term};

fn main() -> io::Result<()> {
    let raw = std::env::args_os().any(|arg| arg == "-r" || arg == "--raw");
    let term = Term::stdout();
    term.write_line("Press any key. Esc to exit")?;
    loop {
        let key = if raw {
            term.read_key_raw()
        } else {
            term.read_key()
        }?;
        term.write_line(&format!("You pressed {:?}", key))?;
        if key == Key::Escape {
            break;
        }
    }
    Ok(())
}
