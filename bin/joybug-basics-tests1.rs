#[tokio::main]
async fn main() -> anyhow::Result<()> {
    joybug2::init_tracing();
    joybug2::run().await
} 