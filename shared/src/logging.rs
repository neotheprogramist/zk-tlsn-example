use tracing::Level;
use tracing_subscriber::fmt::format::FmtSpan;

pub fn init_test_logging() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG)
        .with_target(true)
        .with_file(true)
        .with_line_number(true)
        .with_span_events(FmtSpan::NONE)
        .with_test_writer()
        .try_init();
}
