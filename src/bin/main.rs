use moella::*;

#[tokio::main]
async fn main() {
    let sh = run(&config::CustomExtensions::empty()).await;
    sh.wait().await;
}
