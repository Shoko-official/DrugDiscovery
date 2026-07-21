use std::{
    convert::Infallible,
    error::Error,
    fmt,
    future::Future,
    io,
    net::{SocketAddr, TcpListener as StdTcpListener},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};

use http::{Request, Response};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::{AcquireError, OwnedSemaphorePermit, Semaphore, TryAcquireError, oneshot},
};
use tokio_stream::Stream;
use tonic::{
    Status,
    body::Body,
    transport::{
        Server as TonicServer, ServerTlsConfig,
        server::{Connected, TcpIncoming},
    },
};
use tower::{Layer, Service};

use bioworld_decision_grpc::{
    DECISION_GRPC_REQUEST_DEADLINE_MESSAGE, DecisionGrpcService, TenantAuthenticator,
    TenantScopedGetDecisionExecutor,
};

use crate::{DecisionGrpcServerConfig, DecisionGrpcTlsIdentity};

/// A TLS-configured, bound, and globally connection-bounded decision gRPC server.
pub struct DecisionGrpcServer {
    transport: TonicServer,
    incoming: BoundedTcpIncoming,
    connection_shutdown: Arc<Semaphore>,
    local_addr: SocketAddr,
    config: DecisionGrpcServerConfig,
}

impl DecisionGrpcServer {
    /// Builds TLS before binding the configured socket.
    pub async fn bind(
        config: DecisionGrpcServerConfig,
        identity: DecisionGrpcTlsIdentity,
    ) -> Result<Self, BindDecisionGrpcServerError> {
        let limits = config.limits();
        let tls = ServerTlsConfig::new()
            .identity(identity.into_tonic())
            .timeout(limits.tls_handshake_timeout());
        let transport = TonicServer::builder()
            .tls_config(tls)
            .map_err(|_| BindDecisionGrpcServerError::TlsIdentityRejected)?
            .concurrency_limit_per_connection(
                limits.max_concurrent_streams_per_connection() as usize
            )
            .load_shed(true)
            .initial_stream_window_size(65_535)
            .initial_connection_window_size(65_535)
            .max_concurrent_streams(limits.max_concurrent_streams_per_connection())
            .max_connection_age(limits.max_connection_age())
            .max_connection_age_grace(limits.connection_age_grace())
            .http2_keepalive_interval(Some(std::time::Duration::from_secs(60)))
            .http2_keepalive_timeout(Some(std::time::Duration::from_secs(10)))
            .http2_adaptive_window(Some(false))
            .http2_max_header_list_size(16_384)
            .accept_http1(false);
        let incoming = bind_incoming(config.bind().socket_addr(), limits.max_active_connections())
            .map_err(|_| BindDecisionGrpcServerError::AddressUnavailable)?;
        let local_addr = incoming
            .local_addr()
            .map_err(|_| BindDecisionGrpcServerError::AddressUnavailable)?;
        let connection_shutdown = Arc::new(Semaphore::new(0));

        Ok(Self {
            transport,
            incoming: BoundedTcpIncoming::new(
                incoming,
                limits.max_active_connections(),
                Arc::clone(&connection_shutdown),
            ),
            connection_shutdown,
            local_addr,
            config,
        })
    }

    /// Returns the actual bound address, including an assigned ephemeral loopback port.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Serves the existing authenticated decision service until shutdown or transport failure.
    ///
    /// Shutdown first stops acceptance, then drains bounded request work until the configured
    /// deadline. The returned future owns all listener state and does not install signal handlers.
    pub async fn serve<A, E, F>(
        self,
        service: DecisionGrpcService<A, E>,
        shutdown: F,
    ) -> Result<(), ServeDecisionGrpcServerError>
    where
        A: TenantAuthenticator + 'static,
        E: TenantScopedGetDecisionExecutor + 'static,
        F: Future<Output = ()> + Send + 'static,
    {
        let Self {
            transport,
            incoming,
            connection_shutdown,
            config,
            local_addr: _,
        } = self;
        let connection_lifetime = CloseConnectionsOnDrop(connection_shutdown);
        if service.request_timeout() >= config.limits().shutdown_grace() {
            return Err(ServeDecisionGrpcServerError::ServiceLimitsRejected);
        }
        let (shutdown_started_tx, mut shutdown_started_rx) = oneshot::channel();
        let transport_shutdown = async move {
            shutdown.await;
            let _ = shutdown_started_tx.send(());
        };
        let mut transport = transport.layer(RequestTimeoutLayer {
            timeout: config.limits().transport_request_timeout(),
        });
        let router = transport.add_service(service.into_server());
        let serving = router.serve_with_incoming_shutdown(incoming, transport_shutdown);
        tokio::pin!(serving);

        tokio::select! {
            result = &mut serving => map_serve_result(result),
            shutdown_started = &mut shutdown_started_rx => {
                if shutdown_started.is_err() {
                    return map_serve_result(serving.await);
                }
                match tokio::time::timeout(config.limits().shutdown_grace(), &mut serving).await {
                    Ok(result) => map_serve_result(result),
                    Err(_) => {
                        connection_lifetime.close();
                        match map_serve_result(serving.await) {
                            Ok(()) => Err(ServeDecisionGrpcServerError::ShutdownDeadlineExceeded),
                            Err(error) => Err(error),
                        }
                    },
                }
            }
        }
    }
}

impl fmt::Debug for DecisionGrpcServer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DecisionGrpcServer")
    }
}

/// Fixed startup failure categories without TLS or address detail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BindDecisionGrpcServerError {
    /// The certificate chain or private key was malformed or mismatched.
    TlsIdentityRejected,
    /// The configured socket could not be created or bound.
    AddressUnavailable,
}

impl fmt::Display for BindDecisionGrpcServerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TlsIdentityRejected => {
                formatter.write_str("decision gRPC server TLS identity is rejected")
            }
            Self::AddressUnavailable => {
                formatter.write_str("decision gRPC server address is unavailable")
            }
        }
    }
}

impl Error for BindDecisionGrpcServerError {}

/// Fixed serving failure categories without transport internals.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServeDecisionGrpcServerError {
    /// Tonic transport terminated unexpectedly.
    TransportFailure,
    /// Graceful shutdown did not finish within its validated deadline.
    ShutdownDeadlineExceeded,
    /// The service request budget cannot drain before forced shutdown.
    ServiceLimitsRejected,
}

impl fmt::Display for ServeDecisionGrpcServerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TransportFailure => formatter.write_str("decision gRPC server transport failed"),
            Self::ShutdownDeadlineExceeded => {
                formatter.write_str("decision gRPC server shutdown deadline exceeded")
            }
            Self::ServiceLimitsRejected => {
                formatter.write_str("decision gRPC server service limits are rejected")
            }
        }
    }
}

impl Error for ServeDecisionGrpcServerError {}

fn map_serve_result(
    result: Result<(), tonic::transport::Error>,
) -> Result<(), ServeDecisionGrpcServerError> {
    result.map_err(|_| ServeDecisionGrpcServerError::TransportFailure)
}

#[derive(Clone, Copy)]
struct RequestTimeoutLayer {
    timeout: std::time::Duration,
}

impl<S> Layer<S> for RequestTimeoutLayer {
    type Service = RequestTimeoutService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RequestTimeoutService {
            inner,
            timeout: self.timeout,
        }
    }
}

#[derive(Clone)]
struct RequestTimeoutService<S> {
    inner: S,
    timeout: std::time::Duration,
}

impl<S> Service<Request<Body>> for RequestTimeoutService<S>
where
    S: Service<Request<Body>, Response = Response<Body>, Error = Infallible> + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(context)
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        let response = self.inner.call(request);
        let timeout = self.timeout;
        Box::pin(async move {
            match tokio::time::timeout(timeout, response).await {
                Ok(result) => result,
                Err(_) => Ok(
                    Status::deadline_exceeded(DECISION_GRPC_REQUEST_DEADLINE_MESSAGE)
                        .into_http::<Body>(),
                ),
            }
        })
    }
}

struct CloseConnectionsOnDrop(Arc<Semaphore>);

impl CloseConnectionsOnDrop {
    fn close(&self) {
        self.0.close();
    }
}

impl Drop for CloseConnectionsOnDrop {
    fn drop(&mut self) {
        self.close();
    }
}

fn bind_incoming(socket_addr: SocketAddr, backlog: usize) -> io::Result<TcpIncoming> {
    let socket = Socket::new(
        Domain::for_address(socket_addr),
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
    if socket_addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.bind(&socket_addr.into())?;
    socket.listen(i32::try_from(backlog).expect("validated backlog must fit i32"))?;
    socket.set_nonblocking(true)?;
    let std_listener: StdTcpListener = socket.into();
    let listener = TcpListener::from_std(std_listener)?;
    Ok(TcpIncoming::from(listener).with_nodelay(Some(true)))
}

type SemaphoreAcquireFuture =
    Pin<Box<dyn Future<Output = Result<OwnedSemaphorePermit, AcquireError>> + Send>>;

struct BoundedTcpIncoming {
    incoming: TcpIncoming,
    admission: Arc<Semaphore>,
    pending_permit: Option<SemaphoreAcquireFuture>,
    connection_shutdown: Arc<Semaphore>,
}

impl BoundedTcpIncoming {
    fn new(
        incoming: TcpIncoming,
        max_active_connections: usize,
        connection_shutdown: Arc<Semaphore>,
    ) -> Self {
        Self {
            incoming,
            admission: Arc::new(Semaphore::new(max_active_connections)),
            pending_permit: None,
            connection_shutdown,
        }
    }

    fn poll_permit(&mut self, context: &mut Context<'_>) -> Poll<Option<OwnedSemaphorePermit>> {
        if self.pending_permit.is_none() {
            match Arc::clone(&self.admission).try_acquire_owned() {
                Ok(permit) => return Poll::Ready(Some(permit)),
                Err(TryAcquireError::Closed) => return Poll::Ready(None),
                Err(TryAcquireError::NoPermits) => {
                    self.pending_permit =
                        Some(Box::pin(Arc::clone(&self.admission).acquire_owned()));
                }
            }
        }

        let result = ready!(
            self.pending_permit
                .as_mut()
                .expect("pending permit must exist")
                .as_mut()
                .poll(context)
        );
        self.pending_permit = None;
        Poll::Ready(result.ok())
    }
}

impl Stream for BoundedTcpIncoming {
    type Item = io::Result<AdmittedTcpStream>;

    fn poll_next(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let permit = match ready!(this.poll_permit(context)) {
            Some(permit) => permit,
            None => return Poll::Ready(None),
        };

        match Pin::new(&mut this.incoming).poll_next(context) {
            Poll::Ready(Some(Ok(stream))) => Poll::Ready(Some(Ok(AdmittedTcpStream {
                stream,
                _permit: permit,
                forced_shutdown: Box::pin(Arc::clone(&this.connection_shutdown).acquire_owned()),
                forced_shutdown_observed: false,
            }))),
            Poll::Ready(Some(Err(error))) => Poll::Ready(Some(Err(error))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

struct AdmittedTcpStream {
    stream: TcpStream,
    _permit: OwnedSemaphorePermit,
    forced_shutdown: SemaphoreAcquireFuture,
    forced_shutdown_observed: bool,
}

impl AdmittedTcpStream {
    fn poll_forced_shutdown(&mut self, context: &mut Context<'_>) -> bool {
        if self.forced_shutdown_observed {
            return true;
        }
        if self.forced_shutdown.as_mut().poll(context).is_ready() {
            self.forced_shutdown_observed = true;
            true
        } else {
            false
        }
    }
}

impl Connected for AdmittedTcpStream {
    type ConnectInfo = <TcpStream as Connected>::ConnectInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        self.stream.connect_info()
    }
}

impl AsyncRead for AdmittedTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        if this.poll_forced_shutdown(context) {
            return Poll::Ready(Err(forced_shutdown_error()));
        }
        Pin::new(&mut this.stream).poll_read(context, buffer)
    }
}

impl AsyncWrite for AdmittedTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.as_mut().get_mut();
        if this.poll_forced_shutdown(context) {
            return Poll::Ready(Err(forced_shutdown_error()));
        }
        Pin::new(&mut this.stream).poll_write(context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        if this.poll_forced_shutdown(context) {
            return Poll::Ready(Err(forced_shutdown_error()));
        }
        Pin::new(&mut this.stream).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        if this.poll_forced_shutdown(context) {
            return Poll::Ready(Err(forced_shutdown_error()));
        }
        Pin::new(&mut this.stream).poll_shutdown(context)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.as_mut().get_mut();
        if this.poll_forced_shutdown(context) {
            return Poll::Ready(Err(forced_shutdown_error()));
        }
        Pin::new(&mut this.stream).poll_write_vectored(context, buffers)
    }
}

fn forced_shutdown_error() -> io::Error {
    io::Error::from(io::ErrorKind::ConnectionAborted)
}

#[cfg(test)]
mod tests {
    use std::{future::poll_fn, net::Ipv4Addr, time::Duration};

    use tokio_stream::StreamExt;

    use super::*;

    async fn guarded<T>(future: impl Future<Output = T>) -> T {
        tokio::time::timeout(Duration::from_secs(3), future)
            .await
            .expect("test operation timed out")
    }

    #[tokio::test]
    async fn connection_permit_is_held_until_the_accepted_stream_drops() {
        let incoming = bind_incoming(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 1).unwrap();
        let address = incoming.local_addr().unwrap();
        let mut incoming = BoundedTcpIncoming::new(incoming, 1, Arc::new(Semaphore::new(0)));

        let _first_client = guarded(TcpStream::connect(address)).await.unwrap();
        let first_stream = guarded(incoming.next()).await.unwrap().unwrap();
        let _second_client = guarded(TcpStream::connect(address)).await.unwrap();
        let second_accept = incoming.next();
        tokio::pin!(second_accept);

        let first_poll = poll_fn(|context| Poll::Ready(second_accept.as_mut().poll(context))).await;
        assert!(first_poll.is_pending());

        drop(first_stream);
        let second_stream = guarded(second_accept).await.unwrap().unwrap();
        drop(second_stream);
    }
}
