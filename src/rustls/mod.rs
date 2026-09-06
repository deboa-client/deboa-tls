use deboa::{
    cert::{Certificate, Identity},
    errors::{ConnectionError, DeboaError},
    Result,
};
use futures_io::{AsyncRead, AsyncWrite};
use futures_rustls::{client::TlsStream, TlsConnector};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
    ClientConfig,
};
use std::{fmt::Display, sync::Arc};

/// Builder for TLS connections using rustls
pub struct TlsConnectionBuilder<'a, B, I, C> {
    tcp_stream: B,
    host: &'a str,
    identity: Option<&'a I>,
    certificate: Option<&'a C>,
    skip_server_verification: bool,
    alpn: Vec<Vec<u8>>,
}

impl<'a, B, I, C> TlsConnectionBuilder<'a, B, I, C>
where
    B: AsyncRead + AsyncWrite + Unpin,
    I: Identity,
    C: Certificate,
    CertificateDer<'static>: TryFrom<&'a C>,
    <CertificateDer<'static> as TryFrom<&'a C>>::Error: Display,
    (CertificateDer<'static>, PrivateKeyDer<'static>): TryFrom<&'a I>,
    <(CertificateDer<'static>, PrivateKeyDer<'static>) as TryFrom<&'a I>>::Error: Display,
{
    /// Creates a new TLS connection builder
    pub fn new(tcp_stream: B, host: &'a str) -> Self {
        Self {
            tcp_stream,
            host,
            identity: None,
            certificate: None,
            skip_server_verification: false,
            alpn: Vec::new(),
        }
    }

    /// Set the identity to use for the connection
    pub fn identity(mut self, identity: Option<&'a I>) -> Self {
        self.identity = identity;
        self
    }

    /// Set the certificate to use for the connection
    pub fn certificate(mut self, certificate: Option<&'a C>) -> Self {
        self.certificate = certificate;
        self
    }

    /// Skip server verification
    pub fn skip_server_verification(mut self, skip_server_verification: bool) -> Self {
        self.skip_server_verification = skip_server_verification;
        self
    }

    /// Set the ALPN protocols to use for the connection
    pub fn alpn(mut self, alpn: Vec<Vec<u8>>) -> Self {
        self.alpn = alpn;
        self
    }

    /// Build the TLS client configuration
    pub async fn connect(self) -> Result<TlsStream<B>> {
        let client_config = {
            if self.skip_server_verification {
                ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(
                        crate::rustls::verify::SkipServerVerification::default(),
                    ))
                    .with_no_client_auth()
            } else {
                #[cfg(feature = "__webpki_rustls_verifier")]
                let config = {
                    let config = ClientConfig::builder_with_protocol_versions(rustls::ALL_VERSIONS);

                    let mut root_store =
                        rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
                    let config = if let Some(ca) = self.certificate {
                        let cert = ca
                            .try_into()
                            .map_err(|e| {
                                DeboaError::Connection(ConnectionError::Tls {
                                    message: format!("Invalid CA certificate: {}", e),
                                })
                            })?;

                        root_store
                            .add(cert)
                            .map_err(|e| {
                                DeboaError::Connection(ConnectionError::Tls {
                                    message: format!(
                                        "Could not add CA certificate to the store: {}",
                                        e
                                    ),
                                })
                            })?;

                        config.with_root_certificates(root_store)
                    } else {
                        config.with_root_certificates(root_store)
                    };

                    config
                };

                #[cfg(feature = "__platform_rustls_verifier")]
                let config = {
                    use rustls_platform_verifier::BuilderVerifierExt;
                    rustls::ClientConfig::builder()
                        .with_protocol_versions(rustls::ALL_VERSIONS)
                        .map_err(|e| {
                            DeboaError::Connection(ConnectionError::Tls {
                                message: format!("Failed to set TLS version: {}", e),
                            })
                        })?
                        .with_platform_verifier()
                };

                let mut config = if let Some(id) = self.identity {
                    let pair: (CertificateDer<'_>, PrivateKeyDer<'_>) = id
                        .try_into()
                        .map_err(|e| {
                            DeboaError::Connection(ConnectionError::Tls {
                                message: format!("Invalid client identity: {}", e),
                            })
                        })?;

                    config
                        .with_client_auth_cert(vec![pair.0], pair.1)
                        .map_err(|e| {
                            DeboaError::Connection(ConnectionError::Tls {
                                message: format!("Failed to set client identity: {}", e),
                            })
                        })?
                } else {
                    config.with_no_client_auth()
                };

                config.enable_early_data = true;

                config.alpn_protocols = self.alpn;

                config
            }
        };

        let connector = TlsConnector::from(Arc::new(client_config));

        let hostname = ServerName::try_from(
            self.host
                .to_string(),
        )
        .map_err(|e| DeboaError::Connection(ConnectionError::Tls { message: e.to_string() }))?;

        connector
            .connect(hostname, self.tcp_stream)
            .await
            .map_err(|e| {
                DeboaError::Connection(ConnectionError::Tls {
                    message: format!("Could not connect to server: {}", e),
                })
            })
    }
}

pub mod verify {
    use rustls::{
        client::danger::{ServerCertVerified, ServerCertVerifier},
        pki_types::{CertificateDer, ServerName, UnixTime},
        Error, SignatureScheme,
    };

    #[derive(Debug, Default)]
    pub struct SkipServerVerification;

    impl ServerCertVerifier for SkipServerVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ED25519,
                SignatureScheme::RSA_PKCS1_SHA256,
            ]
        }
    }
}
