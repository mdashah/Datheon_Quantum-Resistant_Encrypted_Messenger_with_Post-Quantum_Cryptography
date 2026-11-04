use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
enum ClientMsg {
    Register { user: String, public_key: String, token: Option<String> },
    GetKey { user: String },
    Handshake { to: String, ciphertext: String, from_public_key: String },
    Message { to: String, nonce: String, ciphertext: String, timestamp: u64 },
    SaveState { send_key: String, recv_key: String, peer: String },
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type")]
enum ServerMsg {
    Registered { user: String, send_key: Option<String>, recv_key: Option<String>, session_peer: Option<String>, token: Option<String> },
    KeyResponse { user: String, public_key: Option<String> },
    Handshake { from: String, ciphertext: String, from_public_key: String },
    Message { from: String, nonce: String, ciphertext: String, timestamp: u64 },
    Error { reason: String },
    QueueDelivered { count: usize },
}

struct TokenBucket {
    capacity: f64,
    tokens: f64,
    refill_per_sec: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(cap: f64, refill: f64) -> Self {
        Self {
            capacity: cap,
            tokens: cap,
            refill_per_sec: refill,
            last_refill: Instant::now(),
        }
    }
    fn try_consume(&mut self) -> bool {
        let now = Instant::now();
        let dt = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + dt * self.refill_per_sec).min(self.capacity);
        self.last_refill = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[derive(Default)]
struct Registry {
    public_keys: HashMap<String, String>,
    senders: HashMap<String, mpsc::UnboundedSender<ServerMsg>>,
    offline_queue: HashMap<String, Vec<ServerMsg>>,
    ratchets: HashMap<String, (String, String, String)>,
    tokens: HashMap<String, String>,
}

type Shared = Arc<Mutex<Registry>>;
type ReplayCache = Arc<Mutex<HashSet<String>>>;

#[tokio::main]
async fn main() {
    let listener = TcpListener::bind("127.0.0.1:8080").await.expect("bind failed");
    let registry: Shared = Arc::new(Mutex::new(Registry::default()));
    let replay: ReplayCache = Arc::new(Mutex::new(HashSet::new()));

    let evict = replay.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        loop {
            tick.tick().await;
            let mut c = evict.lock().await;
            if c.len() > 100_000 { c.clear(); }
        }
    });

    println!("==================================");
    println!(" Zero-Knowledge Relay Server");
    println!(" ws://127.0.0.1:8080");
    println!("==================================");

    while let Ok((stream, addr)) = listener.accept().await {
        println!("Client connected: {}", addr);
        let reg = registry.clone();
        let rep = replay.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(stream, reg, rep).await {
                eprintln!("[{}] error: {}", addr, e);
            }
        });
    }
}

async fn handle(
    stream: tokio::net::TcpStream,
    registry: Shared,
    replay: ReplayCache,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let ws = accept_async(stream).await?;
    let (mut write, mut read) = ws.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<ServerMsg>();

    let send_task = tokio::spawn(async move {
        while let Some(m) = rx.recv().await {
            if let Ok(j) = serde_json::to_string(&m) {
                if write.send(Message::Text(j.into())).await.is_err() { break; }
            }
        }
    });

    let mut me: Option<String> = None;
    let mut bucket = TokenBucket::new(20.0, 5.0);

    while let Some(frame) = read.next().await {
        let text = match frame {
            Ok(Message::Text(t)) => t.to_string(),
            Ok(Message::Close(_)) => break,
            Ok(_) => continue,
            Err(_) => break,
        };

        let parsed: ClientMsg = match serde_json::from_str(&text) {
            Ok(c) => c,
            Err(e) => {
                let _ = tx.send(ServerMsg::Error { reason: format!("json: {e}") });
                continue;
            }
        };

        let is_first_register = matches!(parsed, ClientMsg::Register { .. }) && me.is_none();
        if !is_first_register && !bucket.try_consume() {
            let _ = tx.send(ServerMsg::Error { reason: "rate limit exceeded".into() });
            continue;
        }

        match parsed {
            ClientMsg::Register { user, public_key, token } => {
                let mut r = registry.lock().await;
                
                let mut assigned_token = token.clone();
                if let Some(existing_token) = r.tokens.get(&user) {
                    if token.as_ref() != Some(existing_token) {
                        let _ = tx.send(ServerMsg::Error { reason: "Username already taken or invalid token".into() });
                        continue;
                    }
                } else {
                    let new_token = format!("{:016x}", rand::random::<u64>());
                    r.tokens.insert(user.clone(), new_token.clone());
                    assigned_token = Some(new_token);
                }

                me = Some(user.clone());
                r.public_keys.insert(user.clone(), public_key.clone());
                r.senders.insert(user.clone(), tx.clone());

                let (saved_send, saved_recv, saved_peer) = match r.ratchets.get(&user) {
                    Some((s, rk, p)) => (Some(s.clone()), Some(rk.clone()), Some(p.clone())),
                    None => (None, None, None),
                };

                let _ = tx.send(ServerMsg::Registered { 
                    user: user.clone(), 
                    send_key: saved_send, 
                    recv_key: saved_recv,
                    session_peer: saved_peer,
                    token: assigned_token,
                });

                if let Some(q) = r.offline_queue.remove(&user) {
                    let n = q.len();
                    for m in q { let _ = tx.send(m); }
                    if n > 0 { let _ = tx.send(ServerMsg::QueueDelivered { count: n }); }
                }
            }

            ClientMsg::SaveState { send_key, recv_key, peer } => {
                if let Some(user) = &me {
                    let mut r = registry.lock().await;
                    r.ratchets.insert(user.clone(), (send_key, recv_key, peer));
                }
            }

            ClientMsg::GetKey { user } => {
                let r = registry.lock().await;
                let k = r.public_keys.get(&user).cloned();
                drop(r);
                let _ = tx.send(ServerMsg::KeyResponse { user, public_key: k });
            }

            ClientMsg::Handshake { to, ciphertext, from_public_key } => {
                let from = match &me {
                    Some(u) => u.clone(),
                    None => {
                        let _ = tx.send(ServerMsg::Error { reason: "register first".into() });
                        continue;
                    }
                };
                let out = ServerMsg::Handshake { from: from.clone(), ciphertext, from_public_key };
                let mut r = registry.lock().await;
                if let Some(ptx) = r.senders.get(&to) {
                    if ptx.send(out.clone()).is_ok() { continue; }
                }
                let q = r.offline_queue.entry(to).or_default();
                if q.len() < 500 { q.push(out); }
            }

            ClientMsg::Message { to, nonce, ciphertext, timestamp } => {
                let from = match &me {
                    Some(u) => u.clone(),
                    None => {
                        let _ = tx.send(ServerMsg::Error { reason: "register first".into() });
                        continue;
                    }
                };

                let rk = format!("{from}|{timestamp}|{nonce}");
                {
                    let mut c = replay.lock().await;
                    if c.contains(&rk) {
                        let _ = tx.send(ServerMsg::Error { reason: "replay detected".into() });
                        continue;
                    }
                    c.insert(rk);
                }

                let out = ServerMsg::Message { from, nonce, ciphertext, timestamp };
                let mut r = registry.lock().await;
                if let Some(ptx) = r.senders.get(&to) {
                    if ptx.send(out.clone()).is_ok() { continue; }
                }
                let q = r.offline_queue.entry(to).or_default();
                if q.len() >= 500 {
                    let _ = tx.send(ServerMsg::Error { reason: "offline queue full".into() });
                } else {
                    q.push(out);
                }
            }
        }
    }

    if let Some(user) = me {
        let mut r = registry.lock().await;
        r.senders.remove(&user);
    }
    let _ = send_task.await;
    Ok(())
}