use joybug2;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing for logging
    joybug2::init_tracing();
    
    println!("Starting joybug2 server...");
    
    // Run the server on the default port
    joybug2::server::run_server().await?;
    
    Ok(())
} 