
use crate::blockchain::Block;
use crate::merkle::{EnergyRecord, MerkleNode};

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

#[cfg(feature = "use_mbedtls")]
use std::sync::Arc;
#[cfg(feature = "use_mbedtls")]
use mbedtls::rng::Rdrand;
#[cfg(feature = "use_mbedtls")]
use mbedtls::ssl::config::{Endpoint, Preset, Transport, AuthMode};
#[cfg(feature = "use_mbedtls")]
use mbedtls::ssl::{Config, Context};
#[cfg(feature = "use_mbedtls")]
use mbedtls::x509::Certificate;
#[cfg(feature = "use_mbedtls")]
use mbedtls::alloc::List as MbedtlsList;

/// Redis configuration
#[derive(Clone, Debug)]
pub struct RedisConfig {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub db: u8,
    pub use_tls: bool,
    pub ca_cert: Option<String>,
}

impl RedisConfig {
    pub fn new(host: &str, port: u16) -> Self {
        Self {
            host: host.to_string(),
            port,
            username: None,
            password: None,
            db: 0,
            use_tls: false,
            ca_cert: None,
        }
    }

    pub fn with_password(mut self, password: &str) -> Self {
        self.password = Some(password.to_string());
        self
    }

    /// Set ACL authentication (username + password)
    pub fn with_auth(mut self, username: &str, password: &str) -> Self {
        self.username = Some(username.to_string());
        self.password = Some(password.to_string());
        self
    }

    pub fn with_db(mut self, db: u8) -> Self {
        self.db = db;
        self
    }

    /// Create config with TLS enabled
    #[cfg(feature = "use_mbedtls")]
    pub fn new_with_tls(host: &str, port: u16, ca_cert: &str) -> Self {
        Self {
            host: host.to_string(),
            port,
            username: None,
            password: None,
            db: 0,
            use_tls: true,
            ca_cert: Some(ca_cert.to_string()),
        }
    }

    /// Create config with TLS and ACL authentication
    #[cfg(feature = "use_mbedtls")]
    pub fn new_with_tls_auth(host: &str, port: u16, ca_cert: &str, username: &str, password: &str) -> Self {
        Self {
            host: host.to_string(),
            port,
            username: Some(username.to_string()),
            password: Some(password.to_string()),
            db: 0,
            use_tls: true,
            ca_cert: Some(ca_cert.to_string()),
        }
    }

    pub fn addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// Redis error types
#[derive(Debug)]
pub enum RedisError {
    ConnectionFailed(String),
    AuthFailed(String),
    CommandFailed(String),
    ProtocolError(String),
    IoError(std::io::Error),
}

impl From<std::io::Error> for RedisError {
    fn from(e: std::io::Error) -> Self {
        RedisError::IoError(e)
    }
}

impl std::fmt::Display for RedisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RedisError::ConnectionFailed(s) => write!(f, "Connection failed: {}", s),
            RedisError::AuthFailed(s) => write!(f, "Auth failed: {}", s),
            RedisError::CommandFailed(s) => write!(f, "Command failed: {}", s),
            RedisError::ProtocolError(s) => write!(f, "Protocol error: {}", s),
            RedisError::IoError(e) => write!(f, "IO error: {}", e),
        }
    }
}

/// Redis response types
#[derive(Debug)]
pub enum RedisValue {
    SimpleString(String),
    Error(String),
    Integer(i64),
    BulkString(Option<String>),
    Array(Vec<RedisValue>),
    Nil,
}

impl RedisValue {
    pub fn is_ok(&self) -> bool {
        matches!(self, RedisValue::SimpleString(s) if s == "OK")
    }

    pub fn as_int(&self) -> Option<i64> {
        match self {
            RedisValue::Integer(i) => Some(*i),
            _ => None,
        }
    }

    pub fn as_string(&self) -> Option<&str> {
        match self {
            RedisValue::SimpleString(s) => Some(s),
            RedisValue::BulkString(Some(s)) => Some(s),
            _ => None,
        }
    }
}

/// Redis connection with TLS support using mbedTLS
#[cfg(not(feature = "use_mbedtls"))]
pub struct RedisConnection {
    tcp: TcpStream,
    config: RedisConfig,
}

#[cfg(feature = "use_mbedtls")]
pub struct RedisConnection {
    tls_ctx: Option<*mut std::ffi::c_void>,
    tcp_box: Option<Box<TcpStream>>,
    #[allow(dead_code)]
    tls_config: Option<Arc<Config>>,
    config: RedisConfig,
    is_tls: bool,
}

#[cfg(feature = "use_mbedtls")]
unsafe impl Send for RedisConnection {}

#[cfg(feature = "use_mbedtls")]
impl Drop for RedisConnection {
    fn drop(&mut self) {
        if let Some(ctx_ptr) = self.tls_ctx.take() {
            if self.is_tls {
                unsafe {
                    let _ = Box::from_raw(ctx_ptr as *mut Context<&mut TcpStream>);
                }
            }
        }
    }
}

impl RedisConnection {
    /// Connect to Redis without TLS
    #[cfg(not(feature = "use_mbedtls"))]
    pub fn connect(config: RedisConfig) -> Result<Self, RedisError> {
        println!("[SGX-REDIS] Connecting to {}...", config.addr());
        
        let tcp = TcpStream::connect(config.addr())
            .map_err(|e| RedisError::ConnectionFailed(e.to_string()))?;
        
        tcp.set_nodelay(true).ok();
        tcp.set_read_timeout(Some(Duration::from_secs(30))).ok();
        tcp.set_write_timeout(Some(Duration::from_secs(30))).ok();
        
        let mut conn = Self { tcp, config };
        conn.init()?;
        
        println!("[SGX-REDIS] Connected successfully");
        Ok(conn)
    }

    /// Connect to Redis with optional TLS
    #[cfg(feature = "use_mbedtls")]
    pub fn connect(config: RedisConfig) -> Result<Self, RedisError> {
        if config.use_tls {
            Self::connect_tls(config)
        } else {
            Self::connect_plain(config)
        }
    }

    #[cfg(feature = "use_mbedtls")]
    fn connect_plain(config: RedisConfig) -> Result<Self, RedisError> {
        println!("[SGX-REDIS] Connecting to {} (plain TCP)...", config.addr());
        
        let tcp = TcpStream::connect(config.addr())
            .map_err(|e| RedisError::ConnectionFailed(e.to_string()))?;
        
        tcp.set_nodelay(true).ok();
        tcp.set_read_timeout(Some(Duration::from_secs(30))).ok();
        tcp.set_write_timeout(Some(Duration::from_secs(30))).ok();
        
        let mut conn = Self { 
            tls_ctx: None,
            tcp_box: Some(Box::new(tcp)),
            tls_config: None,
            config,
            is_tls: false,
        };
        conn.init()?;
        
        println!("[SGX-REDIS] Connected successfully (plain TCP)");
        Ok(conn)
    }

    #[cfg(feature = "use_mbedtls")]
    fn connect_tls(config: RedisConfig) -> Result<Self, RedisError> {
        println!("[SGX-REDIS] Connecting to {} (TLS/mbedTLS)...", config.addr());
        
        let tcp = TcpStream::connect(config.addr())
            .map_err(|e| RedisError::ConnectionFailed(e.to_string()))?;
        
        tcp.set_nodelay(true).ok();
        tcp.set_read_timeout(Some(Duration::from_secs(30))).ok();
        tcp.set_write_timeout(Some(Duration::from_secs(30))).ok();
        
        println!("[SGX-REDIS] Starting TLS handshake...");
        
        // Set up mbedTLS config
        let ca_pem = config.ca_cert.as_ref()
            .ok_or_else(|| RedisError::ConnectionFailed("CA certificate required for TLS".to_string()))?;
        
        let pem = format!("{}\0", ca_pem);
        let cert = Certificate::from_pem(pem.as_bytes())
            .map_err(|e| RedisError::ConnectionFailed(format!("Invalid CA certificate: {:?}", e)))?;
        
        let mut ca_list = MbedtlsList::new();
        ca_list.push(cert);
        let ca_list = Arc::new(ca_list);
        
        let rng = Arc::new(Rdrand);
        let mut tls_config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
        tls_config.set_authmode(AuthMode::Optional);
        tls_config.set_rng(rng);
        tls_config.set_ca_list(ca_list, None);
        let tls_config = Arc::new(tls_config);
        
        let mut tcp_box = Box::new(tcp);
        let mut ctx = Context::new(tls_config.clone());
        let tcp_ptr: *mut TcpStream = tcp_box.as_mut();
        
        unsafe {
            ctx.establish(&mut *tcp_ptr, None)
                .map_err(|e| RedisError::ConnectionFailed(format!("TLS handshake failed: {:?}", e)))?;
        }
        
        println!("[SGX-REDIS] TLS handshake complete, connection encrypted");
        
        let ctx_box = Box::new(ctx);
        let ctx_ptr = Box::into_raw(ctx_box) as *mut std::ffi::c_void;
        
        let mut conn = Self {
            tls_ctx: Some(ctx_ptr),
            tcp_box: Some(tcp_box),
            tls_config: Some(tls_config),
            config,
            is_tls: true,
        };
        conn.init()?;
        
        println!("[SGX-REDIS] Connected successfully (TLS encrypted)");
        Ok(conn)
    }

    // Helper methods for read/write
    #[cfg(feature = "use_mbedtls")]
    fn do_read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.is_tls {
            if let Some(ctx_ptr) = self.tls_ctx {
                unsafe {
                    let ctx = &mut *(ctx_ptr as *mut Context<&mut TcpStream>);
                    return ctx.read(buf);
                }
            }
        } else if let Some(ref mut tcp) = self.tcp_box {
            return tcp.read(buf);
        }
        Err(std::io::Error::new(std::io::ErrorKind::NotConnected, "No connection"))
    }

    #[cfg(feature = "use_mbedtls")]
    fn do_write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        if self.is_tls {
            if let Some(ctx_ptr) = self.tls_ctx {
                unsafe {
                    let ctx = &mut *(ctx_ptr as *mut Context<&mut TcpStream>);
                    return ctx.write_all(buf);
                }
            }
        } else if let Some(ref mut tcp) = self.tcp_box {
            return tcp.write_all(buf);
        }
        Err(std::io::Error::new(std::io::ErrorKind::NotConnected, "No connection"))
    }

    #[cfg(feature = "use_mbedtls")]
    fn do_flush(&mut self) -> std::io::Result<()> {
        if self.is_tls {
            if let Some(ctx_ptr) = self.tls_ctx {
                unsafe {
                    let ctx = &mut *(ctx_ptr as *mut Context<&mut TcpStream>);
                    return ctx.flush();
                }
            }
        } else if let Some(ref mut tcp) = self.tcp_box {
            return tcp.flush();
        }
        Ok(())
    }

    #[cfg(not(feature = "use_mbedtls"))]
    fn do_read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.tcp.read(buf)
    }

    #[cfg(not(feature = "use_mbedtls"))]
    fn do_write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        self.tcp.write_all(buf)
    }

    #[cfg(not(feature = "use_mbedtls"))]
    fn do_flush(&mut self) -> std::io::Result<()> {
        self.tcp.flush()
    }

    /// Initialize connection (AUTH and SELECT)
    fn init(&mut self) -> Result<(), RedisError> {
        // Authenticate with ACL (username + password) or legacy (password only)
        match (&self.config.username.clone(), &self.config.password.clone()) {
            (Some(username), Some(password)) => {
                // Redis 6+ ACL: AUTH username password
                let resp = self.command(&["AUTH", &username, &password])?;
                if !resp.is_ok() {
                    return Err(RedisError::AuthFailed(format!("ACL auth failed: {:?}", resp)));
                }
            }
            (None, Some(password)) => {
                // Legacy: AUTH password
                let resp = self.command(&["AUTH", &password])?;
                if !resp.is_ok() {
                    return Err(RedisError::AuthFailed(format!("{:?}", resp)));
                }
            }
            _ => {}
        }

        // Select database
        if self.config.db > 0 {
            let db_str = self.config.db.to_string();
            let resp = self.command(&["SELECT", &db_str])?;
            if !resp.is_ok() {
                return Err(RedisError::CommandFailed(format!("SELECT failed: {:?}", resp)));
            }
        }

        Ok(())
    }

    /// Send a RESP command and get response
    pub fn command(&mut self, args: &[&str]) -> Result<RedisValue, RedisError> {
        // Build RESP array
        let mut cmd = format!("*{}\r\n", args.len());
        for arg in args {
            cmd.push_str(&format!("${}\r\n{}\r\n", arg.len(), arg));
        }

        self.do_write_all(cmd.as_bytes())?;
        self.do_flush()?;

        self.read_response()
    }

    /// Read a RESP response
    fn read_response(&mut self) -> Result<RedisValue, RedisError> {
        let mut buf = [0u8; 1];
        self.do_read(&mut buf)?;

        match buf[0] {
            b'+' => {
                // Simple string
                let line = self.read_line()?;
                Ok(RedisValue::SimpleString(line))
            }
            b'-' => {
                // Error
                let line = self.read_line()?;
                Ok(RedisValue::Error(line))
            }
            b':' => {
                // Integer
                let line = self.read_line()?;
                let num = line.parse::<i64>()
                    .map_err(|_| RedisError::ProtocolError(format!("Invalid integer: {}", line)))?;
                Ok(RedisValue::Integer(num))
            }
            b'$' => {
                // Bulk string
                let line = self.read_line()?;
                let len = line.parse::<i64>()
                    .map_err(|_| RedisError::ProtocolError(format!("Invalid length: {}", line)))?;
                
                if len < 0 {
                    Ok(RedisValue::Nil)
                } else {
                    let mut data = vec![0u8; len as usize];
                    self.read_exact(&mut data)?;
                    // Read trailing \r\n
                    let mut crlf = [0u8; 2];
                    self.read_exact(&mut crlf)?;
                    let s = String::from_utf8_lossy(&data).to_string();
                    Ok(RedisValue::BulkString(Some(s)))
                }
            }
            b'*' => {
                // Array
                let line = self.read_line()?;
                let len = line.parse::<i64>()
                    .map_err(|_| RedisError::ProtocolError(format!("Invalid array length: {}", line)))?;
                
                if len < 0 {
                    Ok(RedisValue::Nil)
                } else {
                    let mut arr = Vec::with_capacity(len as usize);
                    for _ in 0..len {
                        arr.push(self.read_response()?);
                    }
                    Ok(RedisValue::Array(arr))
                }
            }
            _ => Err(RedisError::ProtocolError(format!("Unknown response type: {}", buf[0] as char))),
        }
    }

    fn read_line(&mut self) -> Result<String, RedisError> {
        let mut line = Vec::new();
        let mut buf = [0u8; 1];
        loop {
            self.do_read(&mut buf)?;
            if buf[0] == b'\r' {
                self.do_read(&mut buf)?; // read \n
                break;
            }
            line.push(buf[0]);
        }
        Ok(String::from_utf8_lossy(&line).to_string())
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), RedisError> {
        let mut total = 0;
        while total < buf.len() {
            let n = self.do_read(&mut buf[total..])?;
            if n == 0 {
                return Err(RedisError::ProtocolError("Unexpected EOF".to_string()));
            }
            total += n;
        }
        Ok(())
    }

    /// PING command
    pub fn ping(&mut self) -> Result<bool, RedisError> {
        let resp = self.command(&["PING"])?;
        Ok(matches!(resp, RedisValue::SimpleString(s) if s == "PONG"))
    }

    /// SET command
    pub fn set(&mut self, key: &str, value: &str) -> Result<bool, RedisError> {
        let resp = self.command(&["SET", key, value])?;
        Ok(resp.is_ok())
    }

    /// GET command
    pub fn get(&mut self, key: &str) -> Result<Option<String>, RedisError> {
        let resp = self.command(&["GET", key])?;
        Ok(resp.as_string().map(|s| s.to_string()))
    }

    /// HSET command (set multiple hash fields)
    pub fn hset(&mut self, key: &str, fields: &[(&str, &str)]) -> Result<i64, RedisError> {
        let mut args: Vec<&str> = vec!["HSET", key];
        for (field, value) in fields {
            args.push(field);
            args.push(value);
        }
        let resp = self.command(&args)?;
        resp.as_int().ok_or_else(|| RedisError::CommandFailed(format!("HSET failed: {:?}", resp)))
    }

    /// RPUSH command (append to list)
    pub fn rpush(&mut self, key: &str, values: &[&str]) -> Result<i64, RedisError> {
        let mut args: Vec<&str> = vec!["RPUSH", key];
        args.extend(values);
        let resp = self.command(&args)?;
        resp.as_int().ok_or_else(|| RedisError::CommandFailed(format!("RPUSH failed: {:?}", resp)))
    }

    /// INCR command (increment and return)
    pub fn incr(&mut self, key: &str) -> Result<i64, RedisError> {
        let resp = self.command(&["INCR", key])?;
        resp.as_int().ok_or_else(|| RedisError::CommandFailed(format!("INCR failed: {:?}", resp)))
    }

    /// HGET command (get a single hash field)
    pub fn hget(&mut self, key: &str, field: &str) -> Result<Option<String>, RedisError> {
        let resp = self.command(&["HGET", key, field])?;
        Ok(resp.as_string().map(|s| s.to_string()))
    }

    /// HGETALL command (get all hash fields)
    pub fn hgetall(&mut self, key: &str) -> Result<Vec<(String, String)>, RedisError> {
        let resp = self.command(&["HGETALL", key])?;
        match resp {
            RedisValue::Array(arr) => {
                let mut result = Vec::new();
                let mut iter = arr.into_iter();
                while let (Some(k), Some(v)) = (iter.next(), iter.next()) {
                    if let (Some(key), Some(val)) = (k.as_string(), v.as_string()) {
                        result.push((key.to_string(), val.to_string()));
                    }
                }
                Ok(result)
            }
            _ => Ok(Vec::new())
        }
    }

    /// KEYS command (find keys matching pattern) - use SCAN in production
    pub fn keys(&mut self, pattern: &str) -> Result<Vec<String>, RedisError> {
        let resp = self.command(&["KEYS", pattern])?;
        match resp {
            RedisValue::Array(arr) => {
                let mut result = Vec::new();
                for item in arr {
                    if let Some(s) = item.as_string() {
                        result.push(s.to_string());
                    }
                }
                Ok(result)
            }
            _ => Ok(Vec::new())
        }
    }

    /// Get the latest block state for a VM
    /// Returns (block_number, chained_root) if found, None if no blocks exist
    pub fn get_latest_block_state(&mut self, vm_name: &str) -> Result<Option<(u64, [u8; 32])>, RedisError> {
        // Find all block keys
        let block_keys = self.keys("block:*")?;
        
        if block_keys.is_empty() {
            return Ok(None);
        }

        let mut latest_block_num: Option<u64> = None;
        let mut latest_chained_root: [u8; 32] = [0u8; 32];
        let mut latest_block_key: Option<String> = None;

        // Find the highest block number for this VM
        for key in block_keys {
            // Get vm_name field from block
            if let Some(stored_vm) = self.hget(&key, "vm_name")? {
                if stored_vm == vm_name {
                    if let Some(block_num_str) = self.hget(&key, "block_number")? {
                        if let Ok(block_num) = block_num_str.parse::<u64>() {
                            if latest_block_num.is_none() || block_num > latest_block_num.unwrap() {
                                latest_block_num = Some(block_num);
                                latest_block_key = Some(key.clone());
                            }
                        }
                    }
                }
            }
        }

        // If we found a block, get its chained_root
        if let Some(key) = latest_block_key {
            if let Some(chained_root_hex) = self.hget(&key, "chained_root")? {
                if let Ok(bytes) = hex::decode(&chained_root_hex) {
                    if bytes.len() == 32 {
                        latest_chained_root.copy_from_slice(&bytes);
                    }
                }
            }
            let block_num = latest_block_num.unwrap();
            println!("[SGX-REDIS] Found existing state for VM '{}': block_number={}, chained_root={}...", 
                     vm_name, block_num, &hex::encode(&latest_chained_root)[..16]);
            return Ok(Some((block_num, latest_chained_root)));
        }

        Ok(None)
    }

    /// Execute multiple commands in a pipeline
    pub fn pipeline(&mut self, commands: &[Vec<String>]) -> Result<Vec<RedisValue>, RedisError> {
        // Build all commands
        let mut cmd_buf = String::new();
        for args in commands {
            cmd_buf.push_str(&format!("*{}\r\n", args.len()));
            for arg in args {
                cmd_buf.push_str(&format!("${}\r\n{}\r\n", arg.len(), arg));
            }
        }

        self.do_write_all(cmd_buf.as_bytes())?;
        self.do_flush()?;

        // Read all responses
        let mut results = Vec::with_capacity(commands.len());
        for _ in 0..commands.len() {
            results.push(self.read_response()?);
        }

        Ok(results)
    }

    pub fn insert_block(&mut self, block: &Block) -> Result<i64, RedisError> {
        let total_start = std::time::Instant::now();

        // Get next block ID
        let block_id = self.incr("block_counter")?;
        let block_key = format!("block:{}", block_id);
        let records_key = format!("records:{}", block_id);
        let merkle_key = format!("merkle:{}", block_id);

        // Insert block metadata as hash
        let block_insert_start = std::time::Instant::now();
        let vm_name = if !block.records.is_empty() {
            block.records[0].vm_name.clone()
        } else {
            "unknown".to_string()
        };

        let block_fields = [
            ("block_number", block.block_number.to_string()),
            ("merkle_root", block.merkle_root_hex()),
            ("prev_chained_root", block.prev_chained_root_hex()),
            ("chained_root", block.chained_root_hex()),
            ("record_count", block.record_count.to_string()),
            ("tree_height", block.tree_height.to_string()),
            ("vm_name", vm_name),
            ("created_at", chrono_timestamp()),
        ];
        
        let block_field_refs: Vec<(&str, &str)> = block_fields.iter()
            .map(|(k, v)| (*k, v.as_str()))
            .collect();
        
        self.hset(&block_key, &block_field_refs)?;
        let block_insert_time = block_insert_start.elapsed().as_secs_f64() * 1000.0;

        // Insert records using pipeline for performance
        let records_start = std::time::Instant::now();
        const BATCH_SIZE: usize = 100;
        let mut commands: Vec<Vec<String>> = Vec::new();
        let mut global_idx: usize = 0;  // Track global position for leaf_hashes
        
        for chunk in block.records.chunks(BATCH_SIZE) {
            let mut rpush_args = vec!["RPUSH".to_string(), records_key.clone()];
            
            for record in chunk.iter() {
                let leaf_hash = if global_idx < block.leaf_hashes.len() {
                    hex::encode(block.leaf_hashes[global_idx])
                } else {
                    String::new()
                };
                global_idx += 1;
                
                // Encode record as simple delimited string for efficiency
                let record_str = format!(
                    "{}|{}|{}|{}|{}|{}|{}",
                    leaf_hash,
                    record.pid,
                    record.cpu_time,
                    record.energy_joules,
                    record.power_watts,
                    record.vm_name,
                    record.timestamp
                );
                rpush_args.push(record_str);
            }
            commands.push(rpush_args);
        }
        
        if !commands.is_empty() {
            self.pipeline(&commands)?;
        }
        let records_time = records_start.elapsed().as_secs_f64() * 1000.0;

        // Insert merkle nodes as hash
        let merkle_start = std::time::Instant::now();
        if !block.internal_nodes.is_empty() {
            let mut commands: Vec<Vec<String>> = Vec::new();
            
            for chunk in block.internal_nodes.chunks(BATCH_SIZE) {
                let mut hset_args = vec!["HSET".to_string(), merkle_key.clone()];
                
                for node in chunk {
                    let key = format!("{}:{}", node.level, node.position);
                    let left = node.left_child.map(|h| hex::encode(h)).unwrap_or_default();
                    let right = node.right_child.map(|h| hex::encode(h)).unwrap_or_default();
                    let value = format!("{}|{}|{}", hex::encode(node.hash), left, right);
                    hset_args.push(key);
                    hset_args.push(value);
                }
                commands.push(hset_args);
            }
            
            if !commands.is_empty() {
                self.pipeline(&commands)?;
            }
        }
        let merkle_time = merkle_start.elapsed().as_secs_f64() * 1000.0;

        let total_time = total_start.elapsed().as_secs_f64() * 1000.0;

        println!("[TIMING-REDIS] Block insert breakdown:");
        println!("[TIMING-REDIS]   block_hash: {:.2}ms", block_insert_time);
        println!("[TIMING-REDIS]   records ({} items): {:.2}ms", block.record_count, records_time);
        println!("[TIMING-REDIS]   merkle_nodes ({} items): {:.2}ms", block.internal_nodes.len(), merkle_time);
        println!("[TIMING-REDIS]   TOTAL: {:.2}ms", total_time);

        println!("[SGX-REDIS] Inserted block {} with {} records and {} merkle nodes", 
                 block.block_number, block.record_count, block.internal_nodes.len());

        Ok(block_id)
    }
}

/// Generate timestamp string
fn chrono_timestamp() -> String {
    // Simple timestamp without chrono dependency
    "2026-02-13T00:00:00Z".to_string()
}
