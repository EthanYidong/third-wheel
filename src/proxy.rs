use hyper::client::conn::Builder;
use hyper::server::conn::Http;
use hyper::upgrade::Upgraded;
use openssl::x509::X509;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use log::info;

use http::{Request, Response};

use tokio_native_tls::{TlsAcceptor, TlsStream};

use crate::{RequestCapture, ResponseCapture};
use crate::certificates::spoof_certificate;
use crate::error::Error;

use log::error;
use std::convert::Infallible;

use crate::{
    certificates::{native_identity, CertificateAuthority},
    MitmLayer,
};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Server};
use http::header::HeaderName;

pub(crate) mod mitm;

async fn upgraded_server<T>(
    upgraded: Upgraded,
    ca: Arc<CertificateAuthority>,
    host: &str,
    port: &str,
    mitm: T
) -> Result<(), Error>
    where
        T: MitmLayer + std::marker::Sync + std::marker::Send + 'static + Clone,
{
    let (target_stream, target_certificate) = connect_to_target_with_tls(host, port).await?;
    let certificate = spoof_certificate(&target_certificate, &ca)?;
    let identity = native_identity(&certificate, &ca.key)?;
    let client = TlsAcceptor::from(native_tls::TlsAcceptor::new(identity)?);
    let client_stream = client.accept(upgraded).await?;

    let remote = Builder::new()
        .handshake::<TlsStream<TcpStream>, Body>(target_stream)
        .await?;
    let connection = remote.1;
    // TODO: will this run forever? Is this essentially a memory leak?
    tokio::spawn(connection.without_shutdown());

    let send_request = Arc::new(Mutex::new(remote.0));

    Http::new()
        .serve_connection(
            client_stream,
            service_fn(move |mut request: Request<Body>| {
                let shared_sender = send_request.clone();
                let mitm = mitm.clone();
                async move {
                    match mitm.capture_request(&request).await {
                        RequestCapture::CircumventedResponse(response) => {
                            return Ok::<Response<Body>, Infallible>(response)
                        }
                        RequestCapture::ModifiedRequest(new_request) => request = new_request,
                        RequestCapture::Continue => {}
                    }

                    // TODO: Understand better how to surface errors here instead of unwrapping
                    *request.uri_mut() = request.uri().path().parse().unwrap();
                    // TODO: don't have this unnecessary overhead every time
                    let proxy_connection: HeaderName =
                        HeaderName::from_lowercase(b"proxy-connection").expect("Infallible: hardcoded header name");
                    request.headers_mut().remove(&proxy_connection);
                    let mut send_request_unlocked = shared_sender.lock().await;
                    let mut response = send_request_unlocked.send_request(request).await.unwrap();

                    match mitm.capture_response(&response).await {
                        ResponseCapture::ModifiedResponse(new_response) => {
                            response = new_response;
                        }
                        ResponseCapture::Continue => {}
                    }
                    Ok::<Response<Body>, Infallible>(response)
                }
            }),
        )
        .await
        .map_err(|err| err.into())
}

/// Run a man-in-the-middle TLS proxy
///
/// * `port` - port to accept requests from clients
/// * `mitm` - A `MitmLayer` to capture and/or modify requests and responses
pub async fn start_mitm<T>(port: u16, mitm: T, ca: CertificateAuthority) -> Result<(), Error>
    where
        T: MitmLayer + std::marker::Sync + std::marker::Send + 'static + Clone,
{
    let ca = Arc::new(ca);
    let addr = format!("127.0.0.1:{}", port);
    info!("mitm proxy listening on {}", addr);
    let addr = addr
        .parse::<SocketAddr>()
        .expect("Infallible: hardcoded address");
    let make_service = make_service_fn(move |_| {
        // While the state was moved into the make_service closure,
        // we need to clone it here because this closure is called
        // once for every connection.
        //
        // Each connection could send multiple requests, so
        // the `Service` needs a clone to handle later requests.
        let ca = ca.clone();
        let mitm = mitm.clone();

        async move {
            Ok::<_, Error>(service_fn(move |req: Request<Body>| {
                let mut res = Response::new(Body::empty());

                // The proxy can only handle CONNECT requests
                if req.method() != http::Method::CONNECT {
                    *res.status_mut() = http::status::StatusCode::BAD_REQUEST;
                } else {
                    let target = target_host_port_from_connect(&req);
                    match target {
                        Ok((host, port)) => {
                            // In the case of a TLS tunnel request we spawn a new
                            // service to handle the upgrade. This will only happen
                            // after the currently running function finishes so we need
                            // to spawn it as a separate future.
                            let ca = ca.clone();
                            let mitm = mitm.clone();
                            tokio::task::spawn(async move {
                                match req.into_body().on_upgrade().await {
                                    Ok(upgraded) => {
                                        if let Err(e) =
                                        upgraded_server(upgraded, ca, &host, &port, mitm).await
                                        {
                                            error!("Proxy failed: {}", e)
                                        }
                                    }
                                    Err(e) => error!("Failed to upgrade to TLS: {}", e),
                                }
                            });
                            *res.status_mut() = http::status::StatusCode::OK;
                        }

                        Err(e) => {
                            error!(
                                "Bad request: unable to parse host from connect request: {}",
                                e
                            );
                            *res.status_mut() = http::status::StatusCode::BAD_REQUEST;
                        }
                    }
                }
                async move { Ok::<_, Infallible>(res) }
            }))
        }
    });
    Server::bind(&addr)
        .serve(make_service)
        .await
        .map_err(|err| err.into())
}

async fn connect_to_target_with_tls(
    host: &str,
    port: &str,
) -> Result<(TlsStream<TcpStream>, X509), Error> {
    let target_stream = TcpStream::connect(format!("{}:{}", host, port)).await?;
    let connector = native_tls::TlsConnector::builder().build()?;
    let tokio_connector = tokio_native_tls::TlsConnector::from(connector);
    let target_stream = tokio_connector.connect(&host, target_stream).await?;
    //TODO: Currently to copy the certificate we do a round trip from one library -> der -> other library. This is inefficient, it should be possible to do it better some how.
    let certificate = &target_stream.get_ref().peer_certificate()?;

    let certificate = match certificate {
        Some(cert) => cert,
        None => {
            return Err(Error::ServerError(
                "Server did not provide a certificate for TLS connection".to_string(),
            ))
        }
    };
    let certificate = openssl::x509::X509::from_der(&certificate.to_der()?)?;

    Ok((target_stream, certificate))
}

fn target_host_port_from_connect(request: &Request<Body>) -> Result<(String, String), Error> {
    let host = request
        .uri()
        .host()
        .map(|x| x.to_string())
        .ok_or(Error::RequestError(
            "No host found on CONNECT request".to_string(),
        ))?;
    let port = request
        .uri()
        .port()
        .map(|x| x.to_string())
        .ok_or(Error::RequestError(
            "No port found on CONNECT request".to_string(),
        ))?;
    Ok((host, port))
}
