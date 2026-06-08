use std::sync::Arc;

use rustls::{client::danger::ServerCertVerifier, pki_types::CertificateDer};

use dquic::prelude::{EndpointAddr, ParameterId, QuicClient};
use dquic::qbase::param::ClientParameters;
use dquic::qinterface::component::route::QuicRouter;
use dquic::qresolve::Source;

use crate::{crypto, proto::ConnectRequest, ClientError, Session, ALPN, MAX_DATAGRAM_FRAME_SIZE};

/// Build the client transport parameters, enabling QUIC datagrams (disabled by default).
fn client_parameters() -> ClientParameters {
    let mut params = dquic::prelude::handy::client_parameters();
    params
        .set(
            ParameterId::MaxDatagramFrameSize,
            MAX_DATAGRAM_FRAME_SIZE as u32,
        )
        .expect("max_datagram_frame_size is a valid client parameter");
    params
}

/// Construct a WebTransport [`Client`] using sane defaults.
#[derive(Clone)]
pub struct ClientBuilder {
    provider: crypto::Provider,
    router: Option<Arc<QuicRouter>>,
}

impl ClientBuilder {
    /// Create a Client builder, which can be used to establish multiple [`Session`]s.
    pub fn new() -> Self {
        Self {
            provider: crypto::default_provider(),
            router: None,
        }
    }

    /// Use a specific QUIC router instead of the process-global one.
    ///
    /// This is primarily useful for tests that need to isolate multiple endpoints in one process.
    pub fn with_router(mut self, router: Arc<QuicRouter>) -> Self {
        self.router = Some(router);
        self
    }

    /// Accept any certificate from the server if it uses a known root CA.
    pub fn with_system_roots(self) -> Result<Client, ClientError> {
        let mut roots = rustls::RootCertStore::empty();

        let native = rustls_native_certs::load_native_certs();
        for err in native.errors {
            tracing::warn!(?err, "failed to load root cert");
        }
        for cert in native.certs {
            if let Err(err) = roots.add(cert) {
                tracing::warn!(?err, "failed to add root cert");
            }
        }

        let crypto = self
            .builder()
            .with_root_certificates(roots)
            .with_no_client_auth();

        self.build(crypto)
    }

    /// Supply certificates for accepted servers instead of using root CAs.
    pub fn with_server_certificates(
        self,
        certs: Vec<CertificateDer>,
    ) -> Result<Client, ClientError> {
        let hashes = certs.iter().map({
            let provider = self.provider.clone();
            move |cert| crypto::sha256(&provider, cert).as_ref().to_vec()
        });

        self.with_server_certificate_hashes(hashes.collect())
    }

    /// Supply sha256 hashes for accepted certificates instead of using root CAs.
    pub fn with_server_certificate_hashes(
        self,
        hashes: Vec<Vec<u8>>,
    ) -> Result<Client, ClientError> {
        let fingerprints = Arc::new(ServerFingerprints {
            provider: self.provider.clone(),
            fingerprints: hashes,
        });

        let crypto = self
            .builder()
            .dangerous()
            .with_custom_certificate_verifier(fingerprints)
            .with_no_client_auth();

        self.build(crypto)
    }

    /// Access dangerous configuration options, such as disabling certificate verification.
    pub fn dangerous(self) -> DangerousClientBuilder {
        DangerousClientBuilder { inner: self }
    }

    fn builder(&self) -> rustls::ConfigBuilder<rustls::ClientConfig, rustls::WantsVerifier> {
        rustls::ClientConfig::builder_with_provider(self.provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
    }

    fn build(self, mut crypto: rustls::ClientConfig) -> Result<Client, ClientError> {
        crypto.alpn_protocols = vec![ALPN.as_bytes().to_vec()];

        let mut builder = QuicClient::builder_with_tls(crypto);
        if let Some(router) = self.router {
            builder = builder.with_router(router);
        }
        let endpoint = builder.with_parameters(client_parameters()).build();

        Ok(Client {
            endpoint: Arc::new(endpoint),
        })
    }
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for dangerous TLS configuration options.
pub struct DangerousClientBuilder {
    inner: ClientBuilder,
}

impl DangerousClientBuilder {
    /// Disable certificate verification entirely.
    ///
    /// This makes the connection vulnerable to man-in-the-middle attacks. Only use this in
    /// secure environments, such as in local development or over a VPN connection.
    pub fn with_no_certificate_verification(self) -> Result<Client, ClientError> {
        let noop = NoCertificateVerification(self.inner.provider.clone());

        let crypto = self
            .inner
            .builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(noop))
            .with_no_client_auth();

        self.inner.build(crypto)
    }
}

/// A client for connecting to a WebTransport server.
#[derive(Clone)]
pub struct Client {
    endpoint: Arc<QuicClient>,
}

impl Client {
    /// Connect to the server.
    pub async fn connect(
        &self,
        request: impl Into<ConnectRequest>,
    ) -> Result<Session, ClientError> {
        let request = request.into();

        let host = request
            .url
            .host_str()
            .ok_or_else(|| ClientError::InvalidDnsName(String::new()))?
            .to_string();
        let port = request.url.port().unwrap_or(443);

        // Resolve the host:port to socket addresses. We use an explicit address list (with the
        // host as the SNI server name) so that a self-signed "localhost" certificate validates.
        let addrs = tokio::net::lookup_host((host.clone(), port))
            .await
            .map_err(|_| ClientError::InvalidDnsName(host.clone()))?;
        let endpoints: Vec<(Source, EndpointAddr)> = addrs
            .map(|addr| (Source::System, EndpointAddr::from(addr)))
            .collect();
        if endpoints.is_empty() {
            return Err(ClientError::InvalidDnsName(host));
        }

        let conn = self
            .endpoint
            .connected_to_with_source(host, endpoints)
            .await
            .map_err(|e| ClientError::Connect(e.to_string()))?;

        Session::connect(conn, request).await
    }
}

#[derive(Debug)]
struct ServerFingerprints {
    provider: crypto::Provider,
    fingerprints: Vec<Vec<u8>>,
}

impl ServerCertVerifier for ServerFingerprints {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let cert_hash = crypto::sha256(&self.provider, end_entity);
        if self
            .fingerprints
            .iter()
            .any(|fingerprint| fingerprint == cert_hash.as_ref())
        {
            return Ok(rustls::client::danger::ServerCertVerified::assertion());
        }

        Err(rustls::Error::InvalidCertificate(
            rustls::CertificateError::UnknownIssuer,
        ))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[derive(Debug)]
pub struct NoCertificateVerification(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
