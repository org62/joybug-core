#[tokio::main]
async fn main() -> anyhow::Result<()> {
    joybug_basics_tests1::init_tracing();
    joybug_basics_tests1::run().await
} 