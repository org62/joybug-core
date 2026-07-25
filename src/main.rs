use joybug_core;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing for logging
    joybug_core::init_tracing();
    
    println!("Starting joybug-core server...");
    
    // Run the server on the default port
    joybug_core::server::run_server().await?;
    
    Ok(())
} 