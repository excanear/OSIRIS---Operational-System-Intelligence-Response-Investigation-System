use axum::Router;

/// Binds a mock metadata server on an ephemeral loopback port and returns
/// its base URL (`http://127.0.0.1:<port>`).
pub(crate) async fn serve(router: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    format!("http://{addr}")
}
