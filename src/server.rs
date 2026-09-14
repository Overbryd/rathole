use crate::config::{Config, ServerConfig, ServerServiceConfig, ServiceType, TransportType};
use crate::config_watcher::{ConfigChange, ServerServiceChange};
use crate::constants::{listen_backoff, UDP_BUFFER_SIZE};
use crate::helper::{generate_proxy_protocol_header, retry_notify_with_deadline, write_and_flush};
use crate::multi_map::MultiMap;
use crate::protocol::Hello::{ControlChannelHello, DataChannelHello};
use crate::protocol::{
    self, read_auth, read_hello, Ack, ControlChannelCmd, DataChannelCmd, Hello, UdpTraffic,
    HASH_WIDTH_IN_BYTES,
};
use crate::transport::{SocketOpts, TcpTransport, Transport, TransportRole};
use anyhow::{anyhow, bail, Context, Result};
use backoff::backoff::Backoff;
use backoff::ExponentialBackoff;

use rand::RngCore;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;
use tokio::io::{self, copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{broadcast, mpsc, OwnedSemaphorePermit, RwLock, Semaphore};
use tokio::task::JoinSet;
use tokio::time;
use tracing::{debug, error, info, info_span, instrument, warn, Instrument, Span};

#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};

#[cfg(feature = "noise")]
use crate::transport::NoiseTransport;
#[cfg(any(feature = "native-tls", feature = "rustls"))]
use crate::transport::TlsTransport;
#[cfg(any(feature = "websocket-native-tls", feature = "websocket-rustls"))]
use crate::transport::WebsocketTransport;

type ServiceDigest = protocol::Digest; // SHA256 of a service name
type Nonce = protocol::Digest; // Also called `session_key`

const TCP_POOL_SIZE: usize = 8; // The number of cached connections for TCP servies
const UDP_POOL_SIZE: usize = 2; // The number of cached connections for UDP services
#[cfg(unix)]
const SOCKET_STREAM_POOL_SIZE: usize = 8; // The number of cached connections for SocketStream services

const CHAN_SIZE: usize = 2048; // The capacity of various chans
const INGRESS_REPORT_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IngressLimit {
    Global,
    Peer,
}

#[derive(Default)]
struct IngressStats {
    completed: AtomicU64,
    failed: AtomicU64,
    timed_out: AtomicU64,
    rejected_global: AtomicU64,
    rejected_peer: AtomicU64,
}

impl IngressStats {
    fn record_limit(&self, limit: IngressLimit) {
        match limit {
            IngressLimit::Global => self.rejected_global.fetch_add(1, Ordering::Relaxed),
            IngressLimit::Peer => self.rejected_peer.fetch_add(1, Ordering::Relaxed),
        };
    }

    fn report(&self, active: usize, peers: usize) {
        let completed = self.completed.swap(0, Ordering::Relaxed);
        let failed = self.failed.swap(0, Ordering::Relaxed);
        let timed_out = self.timed_out.swap(0, Ordering::Relaxed);
        let rejected_global = self.rejected_global.swap(0, Ordering::Relaxed);
        let rejected_peer = self.rejected_peer.swap(0, Ordering::Relaxed);

        if [completed, failed, timed_out, rejected_global, rejected_peer]
            .into_iter()
            .any(|count| count != 0)
        {
            info!(
                target: "rathole::ingress",
                completed,
                failed,
                timed_out,
                rejected_global,
                rejected_peer,
                active,
                peers,
                "Ingress handshake activity"
            );
        }
    }
}

struct IngressLimiter {
    global: Arc<Semaphore>,
    max_global: usize,
    max_per_ip: usize,
    peers: Arc<Mutex<HashMap<IpAddr, usize>>>,
    stats: Arc<IngressStats>,
}

impl IngressLimiter {
    fn new(max_global: usize, max_per_ip: usize) -> Result<Self> {
        if max_global == 0 {
            bail!("Maximum pending handshakes must be greater than zero");
        }
        if max_per_ip == 0 || max_per_ip > max_global {
            bail!("Maximum pending handshakes per IP must be between one and the global limit");
        }

        Ok(Self {
            global: Arc::new(Semaphore::new(max_global)),
            max_global,
            max_per_ip,
            peers: Arc::new(Mutex::new(HashMap::new())),
            stats: Arc::new(IngressStats::default()),
        })
    }

    fn try_acquire(&self, ip: IpAddr) -> std::result::Result<IngressPermit, IngressLimit> {
        let global = match self.global.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                self.stats.record_limit(IngressLimit::Global);
                return Err(IngressLimit::Global);
            }
        };
        let mut peers = self.peers.lock().unwrap_or_else(|e| e.into_inner());
        let active = peers.entry(ip).or_default();
        if *active >= self.max_per_ip {
            self.stats.record_limit(IngressLimit::Peer);
            return Err(IngressLimit::Peer);
        }
        *active += 1;
        drop(peers);

        Ok(IngressPermit {
            _global: global,
            ip,
            peers: self.peers.clone(),
        })
    }

    fn report(&self) {
        let active = self.max_global - self.global.available_permits();
        let peers = self.peers.lock().unwrap_or_else(|e| e.into_inner()).len();
        self.stats.report(active, peers);
    }
}

struct IngressPermit {
    _global: OwnedSemaphorePermit,
    ip: IpAddr,
    peers: Arc<Mutex<HashMap<IpAddr, usize>>>,
}

impl Drop for IngressPermit {
    fn drop(&mut self) {
        let mut peers = self.peers.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(active) = peers.get_mut(&self.ip) {
            *active -= 1;
            if *active == 0 {
                peers.remove(&self.ip);
            }
        }
    }
}

// The entrypoint of running a server
pub async fn run_server(
    config: Config,
    shutdown_rx: broadcast::Receiver<bool>,
    update_rx: mpsc::Receiver<ConfigChange>,
) -> Result<()> {
    let config = match config.server {
            Some(config) => config,
            None => {
                return Err(anyhow!("Try to run as a server, but the configuration is missing. Please add the `[server]` block"))
            }
        };

    match config.transport.transport_type {
        TransportType::Tcp => {
            let mut server = Server::<TcpTransport>::from(config).await?;
            server.run(shutdown_rx, update_rx).await?;
        }
        TransportType::Tls => {
            #[cfg(any(feature = "native-tls", feature = "rustls"))]
            {
                let mut server = Server::<TlsTransport>::from(config).await?;
                server.run(shutdown_rx, update_rx).await?;
            }
            #[cfg(not(any(feature = "native-tls", feature = "rustls")))]
            crate::helper::feature_neither_compile("native-tls", "rustls")
        }
        TransportType::Noise => {
            #[cfg(feature = "noise")]
            {
                let mut server = Server::<NoiseTransport>::from(config).await?;
                server.run(shutdown_rx, update_rx).await?;
            }
            #[cfg(not(feature = "noise"))]
            crate::helper::feature_not_compile("noise")
        }
        TransportType::Websocket => {
            #[cfg(any(feature = "websocket-native-tls", feature = "websocket-rustls"))]
            {
                let mut server = Server::<WebsocketTransport>::from(config).await?;
                server.run(shutdown_rx, update_rx).await?;
            }
            #[cfg(not(any(feature = "websocket-native-tls", feature = "websocket-rustls")))]
            crate::helper::feature_neither_compile("websocket-native-tls", "websocket-rustls")
        }
    }

    Ok(())
}

// A hash map of ControlChannelHandles, indexed by ServiceDigest or Nonce
// See also MultiMap
type ControlChannelMap<T> = MultiMap<ServiceDigest, Nonce, ControlChannelHandle<T>>;

// Server holds all states of running a server
struct Server<T: Transport> {
    // `[server]` config
    config: Arc<ServerConfig>,

    // `[server.services]` config, indexed by ServiceDigest
    services: Arc<RwLock<HashMap<ServiceDigest, ServerServiceConfig>>>,
    // Collection of contorl channels
    control_channels: Arc<RwLock<ControlChannelMap<T>>>,
    // Wrapper around the transport layer
    transport: Arc<T>,
    // Bounds unauthenticated handshakes globally and per source IP
    ingress: IngressLimiter,
}

// Generate a hash map of services which is indexed by ServiceDigest
fn generate_service_hashmap(
    server_config: &ServerConfig,
) -> HashMap<ServiceDigest, ServerServiceConfig> {
    let mut ret = HashMap::new();
    for u in &server_config.services {
        ret.insert(protocol::digest(u.0.as_bytes()), (*u.1).clone());
    }
    ret
}

impl<T: 'static + Transport> Server<T> {
    // Create a server from `[server]`
    pub async fn from(config: ServerConfig) -> Result<Server<T>> {
        let config = Arc::new(config);
        let services = Arc::new(RwLock::new(generate_service_hashmap(&config)));
        let control_channels = Arc::new(RwLock::new(ControlChannelMap::new()));
        let transport = Arc::new(T::new(&config.transport, TransportRole::Server)?);
        let ingress = IngressLimiter::new(
            config.max_pending_handshakes,
            config.max_pending_handshakes_per_ip,
        )?;
        Ok(Server {
            config,
            services,
            control_channels,
            transport,
            ingress,
        })
    }

    // The entry point of Server
    pub async fn run(
        &mut self,
        mut shutdown_rx: broadcast::Receiver<bool>,
        mut update_rx: mpsc::Receiver<ConfigChange>,
    ) -> Result<()> {
        // Listen at `server.bind_addr`
        let l = self
            .transport
            .bind(&self.config.bind_addr)
            .await
            .with_context(|| "Failed to listen at `server.bind_addr`")?;
        info!("Listening at {}", self.config.bind_addr);

        // Retry at least every 100ms
        let mut backoff = ExponentialBackoff {
            max_interval: Duration::from_millis(100),
            max_elapsed_time: None,
            ..Default::default()
        };

        let mut ingress_tasks = JoinSet::new();
        let mut ingress_report = time::interval_at(
            time::Instant::now() + INGRESS_REPORT_INTERVAL,
            INGRESS_REPORT_INTERVAL,
        );
        ingress_report.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

        // Wait for connections and shutdown signals
        loop {
            tokio::select! {
                // Wait for incoming control and data channels
                ret = self.transport.accept(&l) => {
                    match ret {
                        Err(err) => {
                            // Detects whether it's an IO error
                            if let Some(err) = err.downcast_ref::<io::Error>() {
                                // If it is an IO error, then it's possibly an
                                // EMFILE. So sleep for a while and retry
                                // TODO: Only sleep for EMFILE, ENFILE, ENOMEM, ENOBUFS
                                if let Some(d) = backoff.next_backoff() {
                                    error!("Failed to accept: {:#}. Retry in {:?}...", err, d);
                                    time::sleep(d).await;
                                } else {
                                    // This branch will never be executed according to the current retry policy
                                    error!("Too many retries. Aborting...");
                                    break;
                                }
                            }
                            // If it's not an IO error, then it comes from
                            // the transport layer, so just ignore it
                        }
                        Ok((conn, addr)) => {
                            backoff.reset();

                            match self.ingress.try_acquire(addr.ip()) {
                                Ok(permit) => {
                                    let transport = self.transport.clone();
                                    let services = self.services.clone();
                                    let control_channels = self.control_channels.clone();
                                    let server_config = self.config.clone();
                                    let stats = self.ingress.stats.clone();
                                    let timeout = Duration::from_secs(self.config.handshake_timeout);
                                    ingress_tasks.spawn(async move {
                                        let _permit = permit;
                                        match run_ingress_handshake(
                                            conn,
                                            transport,
                                            services,
                                            control_channels,
                                            server_config,
                                            timeout,
                                        )
                                        .await
                                        {
                                            IngressOutcome::Completed => {
                                                stats.completed.fetch_add(1, Ordering::Relaxed);
                                            }
                                            IngressOutcome::Failed(err) => {
                                                stats.failed.fetch_add(1, Ordering::Relaxed);
                                                debug!(error = %err, "Ingress handshake failed");
                                            }
                                            IngressOutcome::TimedOut => {
                                                stats.timed_out.fetch_add(1, Ordering::Relaxed);
                                                debug!("Ingress handshake timed out");
                                            }
                                        }
                                    }.instrument(info_span!("connection", %addr)));
                                }
                                Err(limit) => {
                                    debug!(?limit, %addr, "Ingress handshake rejected");
                                }
                            }
                        }
                    }
                },
                // Wait for the shutdown signal
                _ = shutdown_rx.recv() => {
                    info!("Shuting down gracefully...");
                    break;
                },
                e = update_rx.recv() => {
                    if let Some(e) = e {
                        self.handle_hot_reload(e).await;
                    }
                },
                _ = ingress_report.tick() => {
                    self.ingress.report();
                },
                result = ingress_tasks.join_next(), if !ingress_tasks.is_empty() => {
                    if let Some(Err(err)) = result {
                        error!("Ingress handshake task failed: {err}");
                    }
                }
            }
        }

        ingress_tasks.abort_all();
        while ingress_tasks.join_next().await.is_some() {}
        self.ingress.report();
        info!("Shutdown");

        Ok(())
    }

    async fn handle_hot_reload(&mut self, e: ConfigChange) {
        match e {
            ConfigChange::ServerChange(server_change) => match server_change {
                ServerServiceChange::Add(cfg) => {
                    let hash = protocol::digest(cfg.name.as_bytes());
                    let mut wg = self.services.write().await;
                    let _ = wg.insert(hash, cfg);

                    let mut wg = self.control_channels.write().await;
                    let _ = wg.remove1(&hash);
                }
                ServerServiceChange::Delete(s) => {
                    let hash = protocol::digest(s.as_bytes());
                    let _ = self.services.write().await.remove(&hash);

                    let mut wg = self.control_channels.write().await;
                    let _ = wg.remove1(&hash);
                }
            },
            ignored => warn!("Ignored {:?} since running as a server", ignored),
        }
    }
}

enum IngressOutcome {
    Completed,
    Failed(anyhow::Error),
    TimedOut,
}

async fn run_ingress_handshake<T: 'static + Transport>(
    conn: T::RawStream,
    transport: Arc<T>,
    services: Arc<RwLock<HashMap<ServiceDigest, ServerServiceConfig>>>,
    control_channels: Arc<RwLock<ControlChannelMap<T>>>,
    server_config: Arc<ServerConfig>,
    timeout: Duration,
) -> IngressOutcome {
    let handshake = async {
        let conn = transport
            .handshake(conn)
            .await
            .with_context(|| "Failed to do transport handshake")?;
        handle_connection(conn, services, control_channels, server_config).await
    };

    match time::timeout(timeout, handshake).await {
        Ok(Ok(())) => IngressOutcome::Completed,
        Ok(Err(err)) => IngressOutcome::Failed(err),
        Err(_) => IngressOutcome::TimedOut,
    }
}

// Handle connections to `server.bind_addr`
async fn handle_connection<T: 'static + Transport>(
    mut conn: T::Stream,
    services: Arc<RwLock<HashMap<ServiceDigest, ServerServiceConfig>>>,
    control_channels: Arc<RwLock<ControlChannelMap<T>>>,
    server_config: Arc<ServerConfig>,
) -> Result<()> {
    // Read hello
    let hello = read_hello(&mut conn).await?;
    match hello {
        ControlChannelHello(_, service_digest) => {
            do_control_channel_handshake(
                conn,
                services,
                control_channels,
                service_digest,
                server_config,
            )
            .await?;
        }
        DataChannelHello(_, nonce) => {
            do_data_channel_handshake(conn, control_channels, nonce).await?;
        }
    }
    Ok(())
}

async fn do_control_channel_handshake<T: 'static + Transport>(
    mut conn: T::Stream,
    services: Arc<RwLock<HashMap<ServiceDigest, ServerServiceConfig>>>,
    control_channels: Arc<RwLock<ControlChannelMap<T>>>,
    service_digest: ServiceDigest,
    server_config: Arc<ServerConfig>,
) -> Result<()> {
    debug!("Try to handshake a control channel");

    T::hint(&conn, SocketOpts::for_control_channel());

    // Generate a nonce
    let mut nonce = vec![0u8; HASH_WIDTH_IN_BYTES];
    rand::thread_rng().fill_bytes(&mut nonce);

    // Send hello
    let hello_send = Hello::ControlChannelHello(
        protocol::CURRENT_PROTO_VERSION,
        nonce.clone().try_into().unwrap(),
    );
    conn.write_all(&bincode::serialize(&hello_send).unwrap())
        .await?;
    conn.flush().await?;

    // Lookup the service
    let service_config = match services.read().await.get(&service_digest) {
        Some(v) => v,
        None => {
            conn.write_all(&bincode::serialize(&Ack::ServiceNotExist).unwrap())
                .await?;
            bail!("No such a service {}", hex::encode(service_digest));
        }
    }
    .to_owned();

    let service_name = &service_config.name;

    // Calculate the checksum
    let mut concat = Vec::from(service_config.token.as_ref().unwrap().as_bytes());
    concat.append(&mut nonce);

    // Read auth
    let protocol::Auth(d) = read_auth(&mut conn).await?;

    // Validate
    let session_key = protocol::digest(&concat);
    if session_key != d {
        conn.write_all(&bincode::serialize(&Ack::AuthFailed).unwrap())
            .await?;
        bail!("Service {} failed the authentication", service_name);
    } else {
        let mut h = control_channels.write().await;

        // If there's already a control channel for the service, then drop the old one.
        // Because a control channel doesn't report back when it's dead,
        // the handle in the map could be stall, dropping the old handle enables
        // the client to reconnect.
        if h.remove1(&service_digest).is_some() {
            warn!(
                "Dropping previous control channel for service {}",
                service_name
            );
        }

        // Send ack
        conn.write_all(&bincode::serialize(&Ack::Ok).unwrap())
            .await?;
        conn.flush().await?;

        info!(service = %service_config.name, "Control channel established");
        let handle = ControlChannelHandle::new(
            conn,
            service_config,
            server_config.heartbeat_interval,
            Arc::downgrade(&control_channels),
            session_key,
        );

        // Insert the new handle
        let _ = h.insert(service_digest, session_key, handle);
    }

    Ok(())
}

async fn do_data_channel_handshake<T: 'static + Transport>(
    conn: T::Stream,
    control_channels: Arc<RwLock<ControlChannelMap<T>>>,
    nonce: Nonce,
) -> Result<()> {
    debug!("Try to handshake a data channel");

    // Validate
    let control_channels_guard = control_channels.read().await;
    match control_channels_guard.get2(&nonce) {
        Some(handle) => {
            T::hint(&conn, SocketOpts::from_server_cfg(&handle.service));

            // Send the data channel to the corresponding control channel
            handle
                .data_ch_tx
                .send(conn)
                .await
                .with_context(|| "Data channel for a stale control channel")?;
        }
        None => bail!("Data channel has incorrect nonce"),
    }
    Ok(())
}

pub struct ControlChannelHandle<T: Transport> {
    // Shutdown the control channel by dropping it
    _shutdown_tx: broadcast::Sender<bool>,
    data_ch_tx: mpsc::Sender<T::Stream>,
    service: ServerServiceConfig,
}

impl<T> ControlChannelHandle<T>
where
    T: 'static + Transport,
{
    // Create a control channel handle, where the control channel handling task
    // and the connection pool task are created.
    #[instrument(name = "handle", skip_all, fields(service = %service.name))]
    fn new(
        conn: T::Stream,
        service: ServerServiceConfig,
        heartbeat_interval: u64,
        control_channels: Weak<RwLock<ControlChannelMap<T>>>,
        session_key: Nonce,
    ) -> ControlChannelHandle<T> {
        // Create a shutdown channel
        let (shutdown_tx, shutdown_rx) = broadcast::channel::<bool>(1);

        // Store data channels
        let (data_ch_tx, data_ch_rx) = mpsc::channel(CHAN_SIZE * 2);

        // Store data channel creation requests
        let (data_ch_req_tx, data_ch_req_rx) = mpsc::unbounded_channel();

        // Cache some data channels for later use
        let pool_size = match service.service_type {
            ServiceType::Tcp => TCP_POOL_SIZE,
            ServiceType::Udp => UDP_POOL_SIZE,
            #[cfg(unix)]
            ServiceType::SocketStream => SOCKET_STREAM_POOL_SIZE,
        };

        for _i in 0..pool_size {
            if let Err(e) = data_ch_req_tx.send(true) {
                error!("Failed to request data channel {}", e);
            };
        }

        let shutdown_rx_clone = shutdown_tx.subscribe();
        let bind_addr = service.bind_addr.clone();
        let proxy_protocol = service.proxy_protocol.clone().unwrap_or_default();
        if proxy_protocol == "v1" || proxy_protocol == "v2" {
            info!("Proxy protocol {:?} is enabled", proxy_protocol);
        } else if proxy_protocol.is_empty() {
            info!("Proxy protocol is disabled");
        } else {
            error!("Unknown proxy protocol {}", proxy_protocol);
        }
        match service.service_type {
            ServiceType::Tcp => tokio::spawn(
                async move {
                    if let Err(e) = run_tcp_connection_pool::<T>(
                        bind_addr,
                        proxy_protocol.clone(),
                        data_ch_rx,
                        data_ch_req_tx,
                        shutdown_rx_clone,
                    )
                    .await
                    .with_context(|| "Failed to run TCP connection pool")
                    {
                        error!("{:#}", e);
                    }
                }
                .instrument(Span::current()),
            ),
            ServiceType::Udp => tokio::spawn(
                async move {
                    if let Err(e) = run_udp_connection_pool::<T>(
                        bind_addr,
                        data_ch_rx,
                        data_ch_req_tx,
                        shutdown_rx_clone,
                    )
                    .await
                    .with_context(|| "Failed to run TCP connection pool")
                    {
                        error!("{:#}", e);
                    }
                }
                .instrument(Span::current()),
            ),
            #[cfg(unix)]
            ServiceType::SocketStream => tokio::spawn(
                async move {
                    if let Err(e) = run_socket_stream_connection_pool::<T>(
                        bind_addr,
                        data_ch_rx,
                        data_ch_req_tx,
                        shutdown_rx_clone,
                    )
                    .await
                    .with_context(|| "Failed to run SocketStream connection pool")
                    {
                        error!("{:#}", e);
                    }
                }
                .instrument(Span::current()),
            ),
        };

        // Create the control channel
        let ch = ControlChannel::<T> {
            conn,
            shutdown_rx,
            data_ch_req_rx,
            heartbeat_interval,
        };

        // On exit, drop the handle so `shutdown_tx` drops and the data channel pool
        // closes; otherwise its sockets leak. session_key is unique, so this never
        // removes a reconnected session.
        tokio::spawn(
            async move {
                if let Err(err) = ch.run().await {
                    error!("{:#}", err);
                }
                if let Some(control_channels) = control_channels.upgrade() {
                    control_channels.write().await.remove2(&session_key);
                }
            }
            .instrument(Span::current()),
        );

        ControlChannelHandle {
            _shutdown_tx: shutdown_tx,
            data_ch_tx,
            service,
        }
    }
}

// Control channel, using T as the transport layer. P is TcpStream or UdpTraffic
struct ControlChannel<T: Transport> {
    conn: T::Stream,                               // The connection of control channel
    shutdown_rx: broadcast::Receiver<bool>,        // Receives the shutdown signal
    data_ch_req_rx: mpsc::UnboundedReceiver<bool>, // Receives visitor connections
    heartbeat_interval: u64,                       // Application-layer heartbeat interval in secs
}

impl<T: Transport> ControlChannel<T> {
    // Run a control channel
    #[instrument(skip_all)]
    async fn run(self) -> Result<()> {
        let create_ch_cmd = bincode::serialize(&ControlChannelCmd::CreateDataChannel).unwrap();
        let heartbeat = bincode::serialize(&ControlChannelCmd::HeartBeat).unwrap();

        // Split so we can read (to detect a dead client) and write concurrently.
        let ControlChannel {
            conn,
            mut shutdown_rx,
            mut data_ch_req_rx,
            heartbeat_interval,
        } = self;
        let (mut rd, mut wr) = tokio::io::split(conn);
        let mut probe = [0u8; 1];

        // Wait for data channel requests and the shutdown signal
        loop {
            tokio::select! {
                // The client sends nothing after the handshake, so any completed
                // read means it's gone. Heartbeat writes alone never notice a
                // half-closed client, which leaks its sockets.
                res = rd.read(&mut probe) => {
                    match res {
                        Ok(0) => {
                            debug!("Control channel closed by the client");
                            break;
                        }
                        Ok(bytes_read) => {
                            warn!(bytes_read, "Unexpected data on control channel");
                            break;
                        }
                        Err(e) => {
                            error!("Control channel read error: {:#}", e);
                            break;
                        }
                    }
                },
                val = data_ch_req_rx.recv() => {
                    match val {
                        Some(_) => {
                            if let Err(e) = write_and_flush(&mut wr, &create_ch_cmd).await {
                                error!("{:#}", e);
                                break;
                            }
                        }
                        None => {
                            break;
                        }
                    }
                },
                _ = time::sleep(Duration::from_secs(heartbeat_interval)), if heartbeat_interval != 0 => {
                            if let Err(e) = write_and_flush(&mut wr, &heartbeat).await {
                                error!("{:#}", e);
                                break;
                            }
                }
                // Wait for the shutdown signal
                _ = shutdown_rx.recv() => {
                    break;
                }
            }
        }

        info!("Control channel shutdown");

        Ok(())
    }
}

fn tcp_listen_and_send(
    addr: String,
    data_ch_req_tx: mpsc::UnboundedSender<bool>,
    mut shutdown_rx: broadcast::Receiver<bool>,
) -> mpsc::Receiver<TcpStream> {
    let (tx, rx) = mpsc::channel(CHAN_SIZE);

    tokio::spawn(async move {
        let l = retry_notify_with_deadline(listen_backoff(),  || async {
            Ok(TcpListener::bind(&addr).await?)
        }, |e, duration| {
            error!("{:#}. Retry in {:?}", e, duration);
        }, &mut shutdown_rx).await
        .with_context(|| "Failed to listen for the service");

        let l: TcpListener = match l {
            Ok(v) => v,
            Err(e) => {
                error!("{:#}", e);
                return;
            }
        };

        info!("Listening at {}", &addr);

        // Retry at least every 1s
        let mut backoff = ExponentialBackoff {
            max_interval: Duration::from_secs(1),
            max_elapsed_time: None,
            ..Default::default()
        };

        // Wait for visitors and the shutdown signal
        loop {
            tokio::select! {
                val = l.accept() => {
                    match val {
                        Err(e) => {
                            // `l` is a TCP listener so this must be a IO error
                            // Possibly a EMFILE. So sleep for a while
                            error!("{}. Sleep for a while", e);
                            if let Some(d) = backoff.next_backoff() {
                                time::sleep(d).await;
                            } else {
                                // This branch will never be reached for current backoff policy
                                error!("Too many retries. Aborting...");
                                break;
                            }
                        }
                        Ok((incoming, addr)) => {
                            // For every visitor, request to create a data channel
                            if data_ch_req_tx.send(true).with_context(|| "Failed to send data chan create request").is_err() {
                                // An error indicates the control channel is broken
                                // So break the loop
                                break;
                            }

                            backoff.reset();

                            debug!("New visitor from {}", addr);

                            // Send the visitor to the connection pool
                            let _ = tx.send(incoming).await;
                        }
                    }
                },
                _ = shutdown_rx.recv() => {
                    break;
                }
            }
        }

        info!("TCPListener shutdown");
    }.instrument(Span::current()));

    rx
}

#[cfg(unix)]
fn socket_stream_listen_and_send(
    addr: String,
    data_ch_req_tx: mpsc::UnboundedSender<bool>,
    mut shutdown_rx: broadcast::Receiver<bool>,
) -> mpsc::Receiver<UnixStream> {
    let (tx, rx) = mpsc::channel(CHAN_SIZE);

    tokio::spawn(async move {
        let l = retry_notify_with_deadline(listen_backoff(),  || async {
            if let Ok(exists) = Path::new(&addr).try_exists() {
                if exists {
                    std::fs::remove_file(&addr).unwrap_or_else(|_| error!("Failed to delete stale socket file {}", &addr));
                };
            };
            Ok(UnixListener::bind(&addr)?)
        }, |e, duration| {
            error!("{:#}. Retry in {:?}", e, duration);
        }, &mut shutdown_rx).await
        .with_context(|| "Failed to listen for the service");

        let l: UnixListener = match l {
            Ok(v) => v,
            Err(e) => {
                error!("{:#}", e);
                return;
            }
        };

        info!("Listening at {}", &addr);

        // Retry at least every 1s
        let mut backoff = ExponentialBackoff {
            max_interval: Duration::from_secs(1),
            max_elapsed_time: None,
            ..Default::default()
        };

        // Wait for visitors and the shutdown signal
        loop {
            tokio::select! {
                val = l.accept() => {
                    match val {
                        Err(e) => {
                            // `l` is a Socket listener so this must be a IO error
                            // Possibly a EMFILE. So sleep for a while
                            error!("{}. Sleep for a while", e);
                            if let Some(d) = backoff.next_backoff() {
                                time::sleep(d).await;
                            } else {
                                // This branch will never be reached for current backoff policy
                                error!("Too many retries. Aborting...");
                                break;
                            }
                        }
                        Ok((incoming, addr)) => {
                            // For every visitor, request to create a data channel
                            if data_ch_req_tx.send(true).with_context(|| "Failed to send data channel create request").is_err() {
                                // An error indicates the control channel is broken
                                // So break the loop
                                break;
                            }

                            backoff.reset();

                            debug!("New visitor from {:?}", addr);

                            // Send the visitor to the connection pool
                            let _ = tx.send(incoming).await;
                        }
                    }
                },
                _ = shutdown_rx.recv() => {
                    // cleanup the socket file for SocketStream service
                    if let Ok(exists) = Path::new(&addr).try_exists() {
                        if exists {
                            std::fs::remove_file(&addr).unwrap_or_else(|_| error!("Failed to delete socket file {}", &addr));
                        };
                    };
                    break;
                }
            }
        }

        info!("SocketStreamListener shutdown");
    }.instrument(Span::current()));

    rx
}

#[instrument(skip_all)]
async fn run_tcp_connection_pool<T: Transport>(
    bind_addr: String,
    proxy_protocol: String,
    mut data_ch_rx: mpsc::Receiver<T::Stream>,
    data_ch_req_tx: mpsc::UnboundedSender<bool>,
    shutdown_rx: broadcast::Receiver<bool>,
) -> Result<()> {
    let mut visitor_rx = tcp_listen_and_send(bind_addr, data_ch_req_tx.clone(), shutdown_rx);
    let cmd = bincode::serialize(&DataChannelCmd::StartForwardTcp).unwrap();

    'pool: while let Some(mut visitor) = visitor_rx.recv().await {
        loop {
            if let Some(mut ch) = data_ch_rx.recv().await {
                if write_and_flush(&mut ch, &cmd).await.is_ok() {
                    let proxy_proto = proxy_protocol.clone();
                    tokio::spawn(async move {
                        if !proxy_proto.is_empty() {
                            let proxy_proto_header =
                                generate_proxy_protocol_header(&visitor, &proxy_proto);
                            match proxy_proto_header {
                                Ok(header) => {
                                    let _ = ch.write_all(&header).await;
                                    let _ = ch.flush().await;
                                }
                                Err(e) => {
                                    error!("Failed to generate proxy protocol header: {}", e);
                                }
                            }
                        }
                        let _ = copy_bidirectional(&mut ch, &mut visitor).await;
                    });
                    break;
                } else {
                    // Current data channel is broken. Request for a new one
                    if data_ch_req_tx.send(true).is_err() {
                        break 'pool;
                    }
                }
            } else {
                break 'pool;
            }
        }
    }

    info!("Shutdown");
    Ok(())
}

#[cfg(unix)]
#[instrument(skip_all)]
async fn run_socket_stream_connection_pool<T: Transport>(
    bind_addr: String,
    mut data_ch_rx: mpsc::Receiver<T::Stream>,
    _data_ch_req_tx: mpsc::UnboundedSender<bool>,
    shutdown_rx: broadcast::Receiver<bool>,
) -> Result<()> {
    let mut visitor_rx =
        socket_stream_listen_and_send(bind_addr, _data_ch_req_tx.clone(), shutdown_rx);
    let cmd = bincode::serialize(&DataChannelCmd::StartForwardSocketStream).unwrap();

    'pool: while let Some(mut visitor) = visitor_rx.recv().await {
        loop {
            if let Some(mut ch) = data_ch_rx.recv().await {
                if write_and_flush(&mut ch, &cmd).await.is_ok() {
                    tokio::spawn(async move {
                        let _ = copy_bidirectional(&mut ch, &mut visitor).await;
                    });
                    break;
                } else {
                    // Current data channel is broken. Request for a new one
                    if _data_ch_req_tx.send(true).is_err() {
                        break 'pool;
                    }
                }
            } else {
                break 'pool;
            }
        }
    }

    info!("Shutdown");
    Ok(())
}

#[instrument(skip_all)]
async fn run_udp_connection_pool<T: Transport>(
    bind_addr: String,
    mut data_ch_rx: mpsc::Receiver<T::Stream>,
    _data_ch_req_tx: mpsc::UnboundedSender<bool>,
    mut shutdown_rx: broadcast::Receiver<bool>,
) -> Result<()> {
    // TODO: Load balance

    let l = retry_notify_with_deadline(
        listen_backoff(),
        || async { Ok(UdpSocket::bind(&bind_addr).await?) },
        |e, duration| {
            warn!("{:#}. Retry in {:?}", e, duration);
        },
        &mut shutdown_rx,
    )
    .await
    .with_context(|| "Failed to listen for the service")?;

    info!("Listening at {}", &bind_addr);

    let cmd = bincode::serialize(&DataChannelCmd::StartForwardUdp).unwrap();

    // Receive one data channel
    let mut conn = data_ch_rx
        .recv()
        .await
        .ok_or_else(|| anyhow!("No available data channels"))?;
    write_and_flush(&mut conn, &cmd).await?;

    let mut buf = [0u8; UDP_BUFFER_SIZE];
    loop {
        tokio::select! {
            // Forward inbound traffic to the client
            val = l.recv_from(&mut buf) => {
                let (n, from) = val?;
                UdpTraffic::write_slice(&mut conn, from, &buf[..n]).await?;
            },

            // Forward outbound traffic from the client to the visitor
            hdr_len = conn.read_u8() => {
                let t = UdpTraffic::read(&mut conn, hdr_len?).await?;
                l.send_to(&t.data, t.from).await?;
            }

            _ = shutdown_rx.recv() => {
                break;
            }
        }
    }

    debug!("UDP pool dropped");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::io::ErrorKind;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::ToSocketAddrs;

    const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);

    #[derive(Debug)]
    struct SlowFirstTransport {
        tcp: TcpTransport,
        handshakes_started: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl Transport for SlowFirstTransport {
        type Acceptor = TcpListener;
        type RawStream = TcpStream;
        type Stream = TcpStream;

        fn new(config: &crate::config::TransportConfig, role: TransportRole) -> Result<Self> {
            Ok(Self {
                tcp: TcpTransport::new(config, role)?,
                handshakes_started: Arc::new(AtomicUsize::new(0)),
            })
        }

        fn hint(conn: &Self::Stream, opts: SocketOpts) {
            TcpTransport::hint(conn, opts);
        }

        async fn bind<A: ToSocketAddrs + Send + Sync>(&self, addr: A) -> Result<Self::Acceptor> {
            self.tcp.bind(addr).await
        }

        async fn accept(&self, acceptor: &Self::Acceptor) -> Result<(Self::RawStream, SocketAddr)> {
            self.tcp.accept(acceptor).await
        }

        async fn handshake(&self, conn: Self::RawStream) -> Result<Self::Stream> {
            if self.handshakes_started.fetch_add(1, Ordering::SeqCst) == 0 {
                std::future::pending().await
            } else {
                Ok(conn)
            }
        }

        async fn connect(&self, addr: &crate::transport::AddrMaybeCached) -> Result<Self::Stream> {
            self.tcp.connect(addr).await
        }
    }

    fn unused_tcp_addr() -> Result<SocketAddr> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        Ok(listener.local_addr()?)
    }

    async fn connected_tcp_pair() -> Result<(TcpStream, TcpStream)> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let (client, (server, _)) = tokio::try_join!(TcpStream::connect(addr), listener.accept())?;
        Ok((server, client))
    }

    async fn wait_until_listener_is_bound(addr: SocketAddr) -> Result<()> {
        time::timeout(CLEANUP_TIMEOUT, async {
            loop {
                match TcpListener::bind(addr).await {
                    Ok(listener) => {
                        drop(listener);
                        time::sleep(Duration::from_millis(10)).await;
                    }
                    Err(error) if error.kind() == ErrorKind::AddrInUse => return Ok(()),
                    Err(error) => return Err(error.into()),
                }
            }
        })
        .await
        .context("service listener was not created before the deadline")?
    }

    async fn wait_until_listener_is_released(addr: SocketAddr) -> Result<TcpListener> {
        time::timeout(CLEANUP_TIMEOUT, async {
            loop {
                match TcpListener::bind(addr).await {
                    Ok(listener) => return Ok(listener),
                    Err(error) if error.kind() == ErrorKind::AddrInUse => {
                        time::sleep(Duration::from_millis(10)).await;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        })
        .await
        .context("service listener was not released before the deadline")?
    }

    async fn wait_until_channel_is_removed(
        control_channels: &RwLock<ControlChannelMap<TcpTransport>>,
        service_digest: ServiceDigest,
        session_key: Nonce,
    ) -> Result<()> {
        time::timeout(CLEANUP_TIMEOUT, async {
            loop {
                let removed = {
                    let channels = control_channels.read().await;
                    channels.get1(&service_digest).is_none()
                        && channels.get2(&session_key).is_none()
                };
                if removed {
                    return;
                }
                time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .context("control channel was not removed before the deadline")?;
        Ok(())
    }

    fn tcp_service(bind_addr: SocketAddr) -> ServerServiceConfig {
        ServerServiceConfig {
            service_type: ServiceType::Tcp,
            name: "cleanup-test".to_owned(),
            bind_addr: bind_addr.to_string(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn slow_transport_handshake_does_not_block_accepting_connections() -> Result<()> {
        let server_addr = unused_tcp_addr()?;
        let mut server = Server::<SlowFirstTransport>::from(ServerConfig {
            bind_addr: server_addr.to_string(),
            ..Default::default()
        })
        .await?;
        let handshakes_started = server.transport.handshakes_started.clone();
        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
        let (_update_tx, update_rx) = mpsc::channel(1);
        let server_task = tokio::spawn(async move { server.run(shutdown_rx, update_rx).await });

        let _slow_connection = time::timeout(CLEANUP_TIMEOUT, async {
            loop {
                match TcpStream::connect(server_addr).await {
                    Ok(connection) => return connection,
                    Err(_) => time::sleep(Duration::from_millis(10)).await,
                }
            }
        })
        .await
        .context("server listener was not created before the deadline")?;

        time::timeout(CLEANUP_TIMEOUT, async {
            while handshakes_started.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .context("slow handshake did not start before the deadline")?;

        let mut responsive_connection = TcpStream::connect(server_addr).await?;
        let hello = Hello::ControlChannelHello(
            protocol::CURRENT_PROTO_VERSION,
            protocol::digest(b"missing-service"),
        );
        responsive_connection
            .write_all(&bincode::serialize(&hello)?)
            .await?;

        time::timeout(
            Duration::from_millis(250),
            read_hello(&mut responsive_connection),
        )
        .await
        .context("a slow handshake blocked the accept loop")??;

        let _ = shutdown_tx.send(true);
        time::timeout(CLEANUP_TIMEOUT, server_task)
            .await
            .context("server did not shut down before the deadline")???;
        Ok(())
    }

    #[tokio::test]
    async fn pending_handshake_limit_drops_excess_connections() -> Result<()> {
        let server_addr = unused_tcp_addr()?;
        let mut server = Server::<SlowFirstTransport>::from(ServerConfig {
            bind_addr: server_addr.to_string(),
            max_pending_handshakes: 1,
            max_pending_handshakes_per_ip: 1,
            ..Default::default()
        })
        .await?;
        let handshakes_started = server.transport.handshakes_started.clone();
        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
        let (_update_tx, update_rx) = mpsc::channel(1);
        let server_task = tokio::spawn(async move { server.run(shutdown_rx, update_rx).await });

        let _pending_connection = time::timeout(CLEANUP_TIMEOUT, async {
            loop {
                match TcpStream::connect(server_addr).await {
                    Ok(connection) => return connection,
                    Err(_) => time::sleep(Duration::from_millis(10)).await,
                }
            }
        })
        .await
        .context("server listener was not created before the deadline")?;

        time::timeout(CLEANUP_TIMEOUT, async {
            while handshakes_started.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .context("pending handshake did not start before the deadline")?;

        let mut rejected_connection = TcpStream::connect(server_addr).await?;
        let mut byte = [0_u8; 1];
        let bytes_read = time::timeout(
            Duration::from_millis(250),
            rejected_connection.read(&mut byte),
        )
        .await
        .context("excess connection was not rejected promptly")??;
        assert_eq!(bytes_read, 0);
        assert_eq!(handshakes_started.load(Ordering::SeqCst), 1);

        let _ = shutdown_tx.send(true);
        time::timeout(CLEANUP_TIMEOUT, server_task)
            .await
            .context("server did not shut down before the deadline")???;
        Ok(())
    }

    #[test]
    fn ingress_limiter_bounds_global_and_per_ip_concurrency() -> Result<()> {
        let limiter = IngressLimiter::new(2, 1)?;
        let first_ip = "192.0.2.1".parse()?;
        let second_ip = "192.0.2.2".parse()?;
        let third_ip = "192.0.2.3".parse()?;

        let first = limiter
            .try_acquire(first_ip)
            .map_err(|limit| anyhow!("unexpected ingress limit: {limit:?}"))?;
        assert!(matches!(
            limiter.try_acquire(first_ip),
            Err(IngressLimit::Peer)
        ));

        let second = limiter
            .try_acquire(second_ip)
            .map_err(|limit| anyhow!("unexpected ingress limit: {limit:?}"))?;
        assert!(matches!(
            limiter.try_acquire(third_ip),
            Err(IngressLimit::Global)
        ));

        drop(first);
        let replacement = limiter
            .try_acquire(first_ip)
            .map_err(|limit| anyhow!("unexpected ingress limit: {limit:?}"))?;
        drop(replacement);
        drop(second);

        assert_eq!(limiter.global.available_permits(), 2);
        assert!(limiter
            .peers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn handshake_deadline_includes_protocol_hello() -> Result<()> {
        let (server_conn, mut client_conn) = connected_tcp_pair().await?;
        let transport = Arc::new(TcpTransport::new(
            &Default::default(),
            TransportRole::Server,
        )?);

        let outcome = run_ingress_handshake(
            server_conn,
            transport,
            Arc::new(RwLock::new(HashMap::new())),
            Arc::new(RwLock::new(ControlChannelMap::new())),
            Arc::new(ServerConfig::default()),
            Duration::from_millis(25),
        )
        .await;

        assert!(matches!(outcome, IngressOutcome::TimedOut));
        let mut byte = [0_u8; 1];
        let bytes_read = time::timeout(CLEANUP_TIMEOUT, client_conn.read(&mut byte))
            .await
            .context("timed-out connection was not closed before the deadline")??;
        assert_eq!(bytes_read, 0);
        Ok(())
    }

    #[tokio::test]
    async fn half_closed_control_channel_releases_map_entry_and_listener_without_heartbeat(
    ) -> Result<()> {
        let service_addr = unused_tcp_addr()?;
        let (server_conn, mut client_conn) = connected_tcp_pair().await?;
        let service_digest = [1_u8; HASH_WIDTH_IN_BYTES];
        let session_key = [2_u8; HASH_WIDTH_IN_BYTES];
        let control_channels = Arc::new(RwLock::new(ControlChannelMap::new()));

        {
            // Match the handshake's locking order so cleanup cannot run before insertion.
            let mut channels = control_channels.write().await;
            let handle = ControlChannelHandle::<TcpTransport>::new(
                server_conn,
                tcp_service(service_addr),
                0,
                Arc::downgrade(&control_channels),
                session_key,
            );
            if channels
                .insert(service_digest, session_key, handle)
                .is_err()
            {
                bail!("failed to insert test control channel");
            }
        }

        wait_until_listener_is_bound(service_addr).await?;
        client_conn.shutdown().await?;

        wait_until_channel_is_removed(&control_channels, service_digest, session_key).await?;
        let released_listener = wait_until_listener_is_released(service_addr).await?;
        drop(released_listener);
        drop(client_conn);
        Ok(())
    }

    #[tokio::test]
    async fn dropping_channel_map_releases_listener_without_retaining_cycle() -> Result<()> {
        let service_addr = unused_tcp_addr()?;
        let (server_conn, _client_conn) = connected_tcp_pair().await?;
        let service_digest = [3_u8; HASH_WIDTH_IN_BYTES];
        let session_key = [4_u8; HASH_WIDTH_IN_BYTES];
        let control_channels = Arc::new(RwLock::new(ControlChannelMap::new()));

        {
            let mut channels = control_channels.write().await;
            let handle = ControlChannelHandle::<TcpTransport>::new(
                server_conn,
                tcp_service(service_addr),
                0,
                Arc::downgrade(&control_channels),
                session_key,
            );
            if channels
                .insert(service_digest, session_key, handle)
                .is_err()
            {
                bail!("failed to insert test control channel");
            }
        }

        wait_until_listener_is_bound(service_addr).await?;
        drop(control_channels);

        let released_listener = wait_until_listener_is_released(service_addr).await?;
        drop(released_listener);
        Ok(())
    }
}
