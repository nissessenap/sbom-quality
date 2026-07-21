// fixture only — never executed by the gate; the deps are what matter.
use serde::Serialize;

#[derive(Serialize)]
struct Demo {
    ok: bool,
}

fn main() -> anyhow::Result<()> {
    let _ = Demo { ok: true };
    Ok(())
}
