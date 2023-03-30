use moella::*;

#[cfg(feature = "uring")]
fn main() {
    tokio_uring::start(async {
        let sh = run(&config::CustomExtensions::empty()).await;
        sh.wait().await;
    })
}
#[cfg(not(feature = "uring"))]
#[tokio::main]
async fn main() {
    let sh = run(&config::CustomExtensions::empty()).await;
    sh.wait().await;
}
